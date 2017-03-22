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

use client::{Client, MDataInfo};
use errors::CoreError;
use futures::{Future, IntoFuture};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use nfs::{File, Mode, NfsError, NfsFuture, Reader, Writer};
use routing::{ClientError, EntryActions};
use self_encryption_storage::SelfEncryptionStorage;
use utils::FutureExt;

/// Insert the file into the directory.
pub fn insert<T: AsRef<str>>(client: Client,
                             parent: MDataInfo,
                             name: T,
                             file: &File)
                             -> Box<NfsFuture<()>> {
    let name = name.as_ref();
    trace!("Inserting file with name '{}'", name);

    serialise(&file)
        .map_err(From::from)
        .and_then(|encoded| {
                      let key = parent.enc_entry_key(name.as_bytes())?;
                      let value = parent.enc_entry_value(&encoded)?;

                      Ok((key, value))
                  })
        .into_future()
        .and_then(move |(key, value)| {
                      client.mutate_mdata_entries(parent.name,
                                                  parent.type_tag,
                                                  EntryActions::new().ins(key, value, 0).into())
                  })
        .map_err(From::from)
        .into_box()
}

/// Gets a file from the directory
#[cfg_attr(rustfmt, rustfmt_skip)]
pub fn fetch<S: AsRef<str>>(client: Client,
                            parent: MDataInfo,
                            name: S)
                            -> Box<NfsFuture<(u64, File)>> {
    parent.enc_entry_key(name.as_ref().as_bytes())
        .into_future()
        .and_then(move |key| {
                      client.get_mdata_value(parent.name, parent.type_tag, key)
                          .map(move |value| (value, parent))
                  })
        .and_then(move |(value, parent)| {
                      let plaintext = parent.decrypt(&value.content)?;
                      let file = deserialise(&plaintext)?;
                      Ok((value.entry_version, file))
                  })
        .map_err(convert_error)
        .into_box()
}

/// Returns a reader for reading the file contents
pub fn read(client: Client, file: &File) -> Box<NfsFuture<Reader>> {
    trace!("Reading file {:?}", file);
    Reader::new(client.clone(), SelfEncryptionStorage::new(client), file)
}

/// Delete a file from the Directory
pub fn delete<S: AsRef<str>>(client: &Client,
                             parent: &MDataInfo,
                             name: S,
                             version: u64)
                             -> Box<NfsFuture<()>> {
    let name = name.as_ref();
    trace!("Deleting file with name {}.", name);

    let key = fry!(parent.enc_entry_key(name.as_bytes()));

    client.mutate_mdata_entries(parent.name,
                                parent.type_tag,
                                EntryActions::new().del(key, version).into())
        .map_err(convert_error)
        .into_box()
}

/// Updates the file.
/// If `version` is 0, the current version is first retrieved from the network,
/// and that version incremented by one is then used as the actual version.
pub fn update<S: AsRef<str>>(client: Client,
                             parent: MDataInfo,
                             name: S,
                             file: &File,
                             version: u64)
                             -> Box<NfsFuture<()>> {
    let name = name.as_ref();
    trace!("Updating file with name '{}'", name);

    let client2 = client.clone();

    serialise(&file)
        .map_err(From::from)
        .and_then(|encoded| {
                      let key = parent.enc_entry_key(name.as_bytes())?;
                      let content = parent.enc_entry_value(&encoded)?;

                      Ok((key, content))
                  })
        .into_future()
        .and_then(move |(key, content)| if version != 0 {
                      Ok((key, content, version, parent)).into_future().into_box()
                  } else {
                      client.get_mdata_value(parent.name, parent.type_tag, key.clone())
                          .map(move |value| (key, content, value.entry_version + 1, parent))
                          .into_box()
                  })
        .and_then(move |(key, content, version, parent)| {
            client2.mutate_mdata_entries(parent.name,
                                         parent.type_tag,
                                         EntryActions::new().update(key, content, version).into())
        })
        .map_err(convert_error)
        .into_box()
}

/// Helper function to Update content of a file in a directory. A writer
/// object is returned, through which the data for the file can be written to
/// the network. The file is actually saved in the directory listing only after
/// `writer.close()` is invoked
pub fn update_content<S: Into<String>>(client: Client,
                                       parent: MDataInfo,
                                       name: S,
                                       file: File,
                                       version: u64,
                                       mode: Mode)
                                       -> Box<NfsFuture<Writer>> {
    let name = name.into();
    trace!("Updating content in file with name {}", name);

    Writer::new(client.clone(),
                SelfEncryptionStorage::new(client),
                mode,
                parent,
                file,
                name,
                Some(version))
}

/// Helper function to create a file in a given directory.
/// A writer object is returned, through which the data for the
/// file can be written to the network.
/// The file is actually saved in the directory listing only after
/// `writer.close()` is invoked
pub fn create<S: Into<String>>(client: Client,
                               parent: MDataInfo,
                               name: S,
                               user_metadata: Vec<u8>)
                               -> Box<NfsFuture<Writer>> {
    let name = name.into();
    trace!("Creating file with name {}.", name);

    Writer::new(client.clone(),
                SelfEncryptionStorage::new(client),
                Mode::Overwrite,
                parent,
                File::new(user_metadata),
                name,
                None)
}

// This is different from `impl From<CoreError> for NfsError`, because it maps
// `NoSuchEntry` to `FileNotFound`.
// TODO:  consider performing such conversion directly in the mentioned `impl From`.
fn convert_error(err: CoreError) -> NfsError {
    match err {
        CoreError::RoutingClientError(ClientError::NoSuchEntry) => NfsError::FileNotFound,
        _ => NfsError::from(err),
    }
}

#[cfg(test)]
mod tests {
    use client::{Client, MDataInfo};
    use errors::CoreError;
    use futures::Future;
    use nfs::{File, Mode, NfsFuture, file_helper};
    use utils::FutureExt;
    use utils::test_utils::random_client;

    const APPEND_SIZE: usize = 10;
    const ORIG_SIZE: usize = 100;
    const NEW_SIZE: usize = 50;

    fn create_test_file(client: &Client) -> Box<NfsFuture<(MDataInfo, File)>> {
        let user_root = unwrap!(client.user_root_dir());

        file_helper::create(client.clone(), user_root.clone(), "hello.txt", Vec::new())
            .then(move |res| {
                      let writer = unwrap!(res);

                      writer.write(&[0u8; ORIG_SIZE]).and_then(move |_| writer.close())
                  })
            .map(move |file| (user_root, file))
            .into_box()
    }

    #[test]
    fn file_read() {
        random_client(|client| {
            let c2 = client.clone();

            create_test_file(client)
                .then(move |res| {
                          let (_dir, file) = unwrap!(res);
                          file_helper::read(c2, &file)
                      })
                .then(|res| {
                          let reader = unwrap!(res);
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
    fn file_update_rewrite() {
        random_client(|client| {
            let c2 = client.clone();
            let c3 = client.clone();

            create_test_file(client)
                .then(move |res| {
                    // Updating file - full rewrite
                    let (dir, file) = unwrap!(res);
                    file_helper::update_content(c2, dir, "hello.txt", file, 1, Mode::Overwrite)
                })
                .then(move |res| {
                          let writer = unwrap!(res);
                          writer.write(&[1u8; NEW_SIZE]).and_then(move |_| writer.close())
                      })
                .then(move |res| {
                          let file = unwrap!(res);
                          file_helper::read(c3, &file)
                      })
                .then(|res| {
                          let reader = unwrap!(res);
                          let size = reader.size();
                          println!("reading {} bytes", size);
                          reader.read(0, size)
                      })
                .map(|data| {
                         assert_eq!(data, vec![1u8; 50]);
                     })
        });
    }

    #[test]
    fn file_update_append() {
        random_client(|client| {
            let c2 = client.clone();
            let c3 = client.clone();

            create_test_file(client)
                .then(move |res| {
                          let (dir, file) = unwrap!(res);
                          // Update - should append (after S.E behaviour changed)
                          file_helper::update_content(c2, dir, "hello.txt", file, 1, Mode::Modify)
                      })
                .then(move |res| {
                          let writer = unwrap!(res);
                          writer.write(&[2u8; APPEND_SIZE]).and_then(move |_| writer.close())
                      })
                .then(move |res| {
                          let file = unwrap!(res);
                          file_helper::read(c3, &file)
                      })
                .then(|res| {
                    let reader = unwrap!(res);
                    let size = reader.size();
                    reader.read(0, size).map(move |data| {
                                                 assert_eq!(size, (ORIG_SIZE + APPEND_SIZE) as u64);
                                                 assert_eq!(data[0..ORIG_SIZE].to_owned(),
                                                            vec![0u8; ORIG_SIZE]);
                                                 assert_eq!(&data[ORIG_SIZE..], [2u8; APPEND_SIZE]);
                                             })
                })
        });
    }

    #[test]
    fn file_update_metadata() {
        random_client(|client| {
            let c2 = client.clone();
            let c3 = client.clone();

            create_test_file(client)
                .then(move |res| {
                          let (dir, mut file) = unwrap!(res);
                          file.set_user_metadata(vec![12u8; 10]);
                          file_helper::update(c2, dir, "hello.txt", &file, 1)
                      })
                .then(move |res| {
                          assert!(res.is_ok());
                          file_helper::fetch(c3.clone(), unwrap!(c3.user_root_dir()), "hello.txt")
                      })
                .map(move |(_version, file)| {
                         assert_eq!(*file.user_metadata(), [12u8; 10][..]);
                     })
        });
    }

    #[test]
    fn file_delete() {
        random_client(|client| {
            let c2 = client.clone();
            let c3 = client.clone();

            create_test_file(client)
                .then(move |res| {
                          let (dir, _file) = unwrap!(res);
                          file_helper::delete(&c2, &dir, "hello.txt", 1)
                      })
                .then(move |res| {
                          assert!(res.is_ok());
                          file_helper::fetch(c3.clone(), unwrap!(c3.user_root_dir()), "hello.txt")
                      })
                .then(move |res| -> Result<_, CoreError> {
                    match res {
                        Ok(_) => {
                            // We expect an error in this case
                            panic!("Fetched non-existing file succesfully")
                        }
                        Err(_) => Ok(()),
                    }
                })
        });
    }
}
