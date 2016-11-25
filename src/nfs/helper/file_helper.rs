// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0.
// This, along with the Licenses can be found in the root directory of this
// project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

use core::{Client, FutureExt, SelfEncryptionStorage, immutable_data};
use futures::Future;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use nfs::{Dir, DirId, File, NfsFuture};
use nfs::errors::NfsError;
use nfs::helper::dir_helper;
use nfs::helper::reader::Reader;
use nfs::helper::writer::{Mode, Writer};
use nfs::metadata::FileMetadata;
use routing::{Data, DataIdentifier, XOR_NAME_LEN, XorName};
use rust_sodium::crypto::secretbox;
use self_encryption::DataMap;

/// Helper function to create a file in a directory listing.
/// A writer object is returned, through which the data for the
/// file can be written to the network.
/// The file is actually saved in the directory listing only after
/// `writer.close()` is invoked
pub fn create<S>(client: Client,
                 name: S,
                 user_metadata: Vec<u8>,
                 parent_id: DirId,
                 parent_dir: Dir,
                 is_versioned: bool)
                 -> Box<NfsFuture<Writer>>
    where S: Into<String>
{
    let name = name.into();
    trace!("Creating file with name: {}", name);

    if parent_dir.find_file(&name).is_some() {
        return err!(NfsError::FileAlreadyExistsWithSameName);
    }

    let v0 = FileMetadata::new(name, user_metadata, DataMap::None);

    let file = if !is_versioned {
        File::Unversioned(v0)
    } else {
        File::Versioned {
            ptr_versions: DataIdentifier::Immutable(XorName([0u8; XOR_NAME_LEN])),
            latest_version: v0,
            num_of_versions: 0,
        }
    };

    Writer::new(client.clone(),
                SelfEncryptionStorage::new(client),
                Mode::Overwrite,
                parent_id,
                parent_dir,
                file)
}

/// Delete a file from the Directory
/// Returns Option<parent_directory's parent>
pub fn delete(client: Client,
              file_name: &str,
              parent_id: &DirId,
              parent_dir: &mut Dir)
              -> Box<NfsFuture<()>> {
    trace!("Deleting file with name {}.", file_name);
    let _ = fry!(parent_dir.remove_file(file_name));
    dir_helper::update(client, parent_id, parent_dir)
}

/// Get a list of all file versions
pub fn get_versions(client: &Client,
                    ptr: &DataIdentifier,
                    sk: Option<secretbox::Key>)
                    -> Box<NfsFuture<Vec<FileMetadata>>> {
    match *ptr {
        DataIdentifier::Immutable(ref name) => {
            immutable_data::get_value(client, name, sk)
                .map_err(From::from)
                .and_then(move |versions| Ok(deserialise::<Vec<FileMetadata>>(&versions)?))
                .into_box()
        }
        _ => err!(NfsError::ParameterIsNotValid),
    }

}

/// Updates the file metadata.
/// For versioned files a new file version will be created.
/// Returns the updated parent directory.
pub fn update_metadata<S>(client: Client,
                          prev_name: S,
                          metadata: FileMetadata,
                          parent_id: DirId,
                          mut parent_dir: Dir)
                          -> Box<NfsFuture<Dir>>
    where S: Into<String>
{
    let prev_name = prev_name.into();
    trace!("Updating metadata for file with name '{}'", prev_name);

    let new_file_fut = {
        let orig_file = fry!(parent_dir.find_file(&prev_name).ok_or(NfsError::FileNotFound));

        if prev_name != metadata.name() && parent_dir.find_file(metadata.name()).is_some() {
            return err!(NfsError::FileAlreadyExistsWithSameName);
        }

        match *orig_file {
            File::Versioned { ref latest_version, ref ptr_versions, ref num_of_versions } => {
                let sk = parent_id.1.clone();
                let c2 = client.clone();
                let c3 = client.clone();

                let new_version_count = num_of_versions + 1;
                let latest_version = latest_version.clone();

                get_versions(&client, ptr_versions, sk.clone())
                    .and_then(move |mut versions| {
                        versions.push(latest_version);

                        immutable_data::create(&c2, fry!(serialise(&versions)), sk)
                            .map_err(From::from)
                            .into_box()
                    })
                    .and_then(move |immut_data| {
                        let immut_id = immut_data.identifier();
                        c3.put(Data::Immutable(immut_data), None)
                            .map_err(From::from)
                            .map(move |_| immut_id)
                    })
                    .map(move |new_versions_ptr| {
                        File::Versioned {
                            ptr_versions: new_versions_ptr,
                            num_of_versions: new_version_count,
                            latest_version: metadata,
                        }
                    })
                    .into_box()
            }
            File::Unversioned(_) => ok!(File::Unversioned(metadata)),
        }
    };

    let c2 = client.clone();

    new_file_fut.and_then(move |new_file| {
            parent_dir.update_file(&prev_name, new_file);
            dir_helper::update(c2, &parent_id, &parent_dir)
                .map_err(NfsError::from)
                .map(move |_| parent_dir)
        })
        .into_box()
}

/// Helper function to Update content of a file in a directory listing. A writer
/// object is returned, through which the data for the file can be written to
/// the network. The file is actually saved in the directory listing only after
/// `writer.close()` is invoked
pub fn update_content(client: Client,
                      file: File,
                      mode: Mode,
                      parent_id: DirId,
                      parent_dir: Dir)
                      -> Box<NfsFuture<Writer>> {
    trace!("Updating content in file with name {}", file.name());

    {
        let existing_file = fry!(parent_dir.find_file(file.name())
            .ok_or(NfsError::FileNotFound));

        if *existing_file != file {
            return err!(NfsError::FileDoesNotMatch);
        }
    }

    Writer::new(client.clone(),
                SelfEncryptionStorage::new(client),
                mode,
                parent_id,
                parent_dir,
                file)
}

/// Returns a reader for reading the file contents
pub fn read(client: Client, file: &FileMetadata) -> Result<Reader, NfsError> {
    trace!("Reading file with name: {}", file.name());
    Reader::new(client.clone(), SelfEncryptionStorage::new(client), file)
}

#[cfg(test)]
mod tests {
    use core::Client;
    use core::futures::FutureExt;
    use core::utility::test_utils::random_client;
    use futures::Future;
    use nfs::{Dir, DirId, NfsFuture};
    use nfs::helper::{dir_helper, file_helper};
    use nfs::helper::writer::Mode;

    const APPEND_SIZE: usize = 10;
    const ORIG_SIZE: usize = 100;
    const NEW_SIZE: usize = 50;

    fn create_test_file(client: Client) -> Box<NfsFuture<(Dir, DirId)>> {
        let c2 = client.clone();
        let c3 = client.clone();

        dir_helper::user_root_dir(client.clone())
            .then(move |res| {
                let (parent, parent_id) = unwrap!(res);
                dir_helper::create_sub_dir(c2, "dir", None, Vec::new(), &parent, &parent_id)
            })
            .then(move |res| {
                let (_parent, dir, dir_meta) = unwrap!(res);
                file_helper::create(c3, "hello.txt", Vec::new(), dir_meta.id(), dir, false)
                    .map(move |writer| (writer, dir_meta.id()))
            })
            .then(move |result| {
                let (writer, dir_id) = unwrap!(result);
                writer.write(&[0u8; ORIG_SIZE])
                    .and_then(move |_| writer.close())
                    .map(move |updated_dir| (updated_dir, dir_id))
            })
            .into_box()
    }

    #[test]
    fn file_read() {
        random_client(|client| {
            let c2 = client.clone();

            create_test_file(client.clone())
                .then(move |res| {
                    let (dir, _) = unwrap!(res);
                    let file = unwrap!(dir.find_file("hello.txt"), "File not found");
                    let reader = unwrap!(file_helper::read(c2, file.metadata()));
                    let size = reader.size();
                    println!("reading {} bytes", size);
                    reader.read(0, size)
                })
                .map(move |data| {
                    assert_eq!(data, vec![0u8; 100]);
                })
        });
    }

    #[test]
    fn file_update() {
        random_client(|client| {
            let c2 = client.clone();
            let c3 = client.clone();

            create_test_file(client.clone())
                .then(move |res| {
                    let (dir, metadata) = unwrap!(res);
                    // Update - full rewrite
                    let file = unwrap!(dir.find_file("hello.txt").cloned(), "File not found");
                    file_helper::update_content(c2, file, Mode::Overwrite, metadata, dir)
                })
                .then(move |res| {
                    let writer = unwrap!(res);
                    writer.write(&[1u8; NEW_SIZE])
                        .and_then(move |_| writer.close())
                })
                .then(move |res| {
                    let dir = unwrap!(res);
                    let file = unwrap!(dir.find_file("hello.txt"), "File not found");

                    let reader = unwrap!(file_helper::read(c3, file.metadata()));
                    let size = reader.size();
                    println!("reading {} bytes", size);
                    reader.read(0, size)
                })
                .map(move |data| {
                    assert_eq!(data, vec![1u8; 50]);
                })
        });
    }

    #[test]
    fn file_update_append() {
        random_client(|client| {
            let c2 = client.clone();
            let c3 = client.clone();

            create_test_file(client.clone())
                .then(move |res| {
                    let (dir, metadata) = unwrap!(res);
                    // Update - should append (after S.E behaviour changed)
                    let file = unwrap!(dir.find_file("hello.txt").cloned(), "File not found");
                    file_helper::update_content(c2, file, Mode::Modify, metadata, dir)
                })
                .then(move |res| {
                    let writer = unwrap!(res);
                    writer.write(&[2u8; APPEND_SIZE])
                        .and_then(move |_| writer.close())
                })
                .then(move |res| {
                    let dir = unwrap!(res);
                    let file = unwrap!(dir.find_file("hello.txt"), "File not found");

                    let reader = unwrap!(file_helper::read(c3, file.metadata()));
                    let size = reader.size();
                    reader.read(0, size)
                        .map(move |data| {
                            assert_eq!(size, (ORIG_SIZE + APPEND_SIZE) as u64);
                            assert_eq!(data[0..ORIG_SIZE].to_owned(), vec![0u8; ORIG_SIZE]);
                            assert_eq!(&data[ORIG_SIZE..], [2u8; APPEND_SIZE]);
                        })
                })
        });
    }

    #[test]
    fn file_update_metadata() {
        random_client(|client| {
            let c2 = client.clone();

            create_test_file(client.clone())
                .then(move |res| {
                    let (dir, dir_metadata) = unwrap!(res);
                    // Update Metadata
                    let file = unwrap!(dir.find_file("hello.txt").cloned(), "File not found");
                    let mut new_metadata = file.metadata().clone();
                    new_metadata.set_name("hello.jpg");
                    new_metadata.set_user_metadata(vec![12u8; 10]);
                    file_helper::update_metadata(c2, "hello.txt", new_metadata, dir_metadata, dir)
                        .map(move |dir| dir)
                })
                .map(|dir| {
                    let file = unwrap!(dir.find_file("hello.jpg").cloned(), "File not found");
                    assert_eq!(*file.metadata().user_metadata(), [12u8; 10][..]);
                })
        });
    }

    #[test]
    fn file_delete() {
        random_client(|client| {
            let c2 = client.clone();

            create_test_file(client.clone()).and_then(move |(mut dir, metadata)| {
                file_helper::delete(c2, "hello.txt", &metadata, &mut dir).map(move |_| {
                    assert!(dir.find_file("hello.txt").is_none());
                })
            })
        })
    }
}
