// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use client::{Client, MDataInfo};
use crypto::shared_secretbox;
use errors::CoreError;
use futures::{Future, IntoFuture};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use nfs::{File, Mode, NfsError, NfsFuture, Reader, Writer};
use routing::{ClientError, EntryActions};
use self_encryption_storage::SelfEncryptionStorage;
use utils::FutureExt;

/// Insert the file into the directory.
pub fn insert<S, T>(
    client: Client<T>,
    parent: MDataInfo,
    name: S,
    file: &File,
) -> Box<NfsFuture<()>>
where
    S: AsRef<str>,
    T: 'static,
{
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
            client.mutate_mdata_entries(
                parent.name,
                parent.type_tag,
                EntryActions::new().ins(key, value, 0).into(),
            )
        })
        .map_err(From::from)
        .into_box()
}

/// Gets a file from the directory
pub fn fetch<S, T>(client: Client<T>, parent: MDataInfo, name: S) -> Box<NfsFuture<(u64, File)>>
where
    S: AsRef<str>,
    T: 'static,
{
    parent
        .enc_entry_key(name.as_ref().as_bytes())
        .into_future()
        .and_then(move |key| {
            client
                .get_mdata_value(parent.name, parent.type_tag, key)
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
pub fn read<T: 'static>(
    client: Client<T>,
    file: &File,
    encryption_key: Option<shared_secretbox::Key>,
) -> Box<NfsFuture<Reader<T>>> {
    trace!("Reading file {:?}", file);
    Reader::new(
        client.clone(),
        SelfEncryptionStorage::new(client),
        file,
        encryption_key,
    )
}

/// Delete a file from the Directory
pub fn delete<S, T>(
    client: &Client<T>,
    parent: &MDataInfo,
    name: S,
    version: u64,
) -> Box<NfsFuture<()>>
where
    S: AsRef<str>,
    T: 'static,
{
    let name = name.as_ref();
    trace!("Deleting file with name {}.", name);

    let key = fry!(parent.enc_entry_key(name.as_bytes()));

    client
        .mutate_mdata_entries(
            parent.name,
            parent.type_tag,
            EntryActions::new().del(key, version).into(),
        )
        .map_err(convert_error)
        .into_box()
}

/// Updates the file.
/// If `version` is 0, the current version is first retrieved from the network,
/// and that version incremented by one is then used as the actual version.
pub fn update<S, T>(
    client: Client<T>,
    parent: MDataInfo,
    name: S,
    file: &File,
    version: u64,
) -> Box<NfsFuture<()>>
where
    S: AsRef<str>,
    T: 'static,
{
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
            ok!((key, content, version, parent))
        } else {
            client
                .get_mdata_value(parent.name, parent.type_tag, key.clone())
                .map(move |value| (key, content, value.entry_version + 1, parent))
                .into_box()
        })
        .and_then(move |(key, content, version, parent)| {
            client2.mutate_mdata_entries(
                parent.name,
                parent.type_tag,
                EntryActions::new().update(key, content, version).into(),
            )
        })
        .map_err(convert_error)
        .into_box()
}

/// Helper function to Update content of a file in a directory. A writer
/// object is returned, through which the data for the file can be written to
/// the network. The file is actually saved in the directory listing only after
/// `writer.close()` is invoked
pub fn write<T>(
    client: Client<T>,
    file: File,
    mode: Mode,
    encryption_key: Option<shared_secretbox::Key>,
) -> Box<NfsFuture<Writer<T>>>
where
    T: 'static,
{
    trace!("Creating a writer for a file");

    Writer::new(
        client.clone(),
        SelfEncryptionStorage::new(client),
        file,
        mode,
        encryption_key,
    )
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
    use DIR_TAG;
    use client::{Client, MDataInfo};
    use crypto::shared_secretbox;
    use errors::CoreError;
    use futures::Future;
    use nfs::{File, Mode, NfsError, NfsFuture, create_dir, file_helper};
    use rand::{self, Rng};
    use utils::FutureExt;
    use utils::test_utils::random_client;

    const APPEND_SIZE: usize = 10;
    const ORIG_SIZE: usize = 100;
    const NEW_SIZE: usize = 50;

    fn create_test_file(client: &Client<()>) -> Box<NfsFuture<(MDataInfo, File)>> {
        let c2 = client.clone();
        let c3 = client.clone();
        let root = unwrap!(MDataInfo::random_private(DIR_TAG));
        let root2 = root.clone();

        create_dir(client, &root, btree_map![], btree_map![])
            .then(move |res| {
                assert!(res.is_ok());

                file_helper::write(
                    c2.clone(),
                    File::new(Vec::new()),
                    Mode::Overwrite,
                    root.enc_key().cloned(),
                )
            })
            .then(move |res| {
                let writer = unwrap!(res);

                writer.write(&[0u8; ORIG_SIZE]).and_then(
                    move |_| writer.close(),
                )
            })
            .then(move |res| {
                let file = unwrap!(res);

                file_helper::insert(c3, root2.clone(), "hello.txt", &file)
                    .map(move |_| (root2, file))
            })
            .into_box()
    }

    // Create a file and open it for reading.
    // Additionally test that the created and modified timestamps are correct.
    #[test]
    fn file_read() {
        random_client(|client| {
            let c2 = client.clone();

            create_test_file(client)
                .then(move |res| {
                    let (dir, file) = unwrap!(res);
                    let creation_time = *file.created_time();

                    file_helper::read(c2, &file, dir.enc_key().cloned()).map(
                        move |reader| (reader, file, creation_time),
                    )
                })
                .then(|res| {
                    let (reader, file, creation_time) = unwrap!(res);
                    let size = reader.size();
                    println!("reading {} bytes", size);
                    let result = reader.read(0, size);

                    assert_eq!(creation_time, *file.created_time());
                    assert!(creation_time <= *file.modified_time());

                    result
                })
                .map(move |data| {
                    assert_eq!(data, vec![0u8; 100]);
                })
        });
    }

    // Test writing to a file in Overwrite mode.
    // Additionally test that the created and modified timestamps are correct.
    #[test]
    fn file_update_overwrite() {
        random_client(|client| {
            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();
            let c5 = client.clone();

            create_test_file(client)
                .then(move |res| {
                    // Updating file - full rewrite
                    let (dir, file) = unwrap!(res);
                    let creation_time = *file.created_time();

                    file_helper::write(c2, file, Mode::Overwrite, dir.enc_key().cloned())
                        .map(move |writer| (writer, dir, creation_time))
                })
                .then(move |res| {
                    let (writer, dir, creation_time) = unwrap!(res);
                    writer
                        .write(&[1u8; NEW_SIZE])
                        .and_then(move |_| writer.close())
                        .map(move |file| (file, dir, creation_time))
                })
                .then(move |res| {
                    let (file, dir, creation_time) = unwrap!(res);
                    file_helper::update(c3, dir.clone(), "hello.txt", &file, 1)
                        .map(move |_| (dir, creation_time))
                })
                .then(move |res| {
                    let (dir, creation_time) = unwrap!(res);
                    let fut = file_helper::fetch(c4, dir.clone(), "hello.txt");
                    fut.map(move |(version, file)| (dir, version, file, creation_time))
                })
                .then(move |res| {
                    let (dir, _version, file, creation_time) = unwrap!(res);

                    // Check file timestamps
                    assert_eq!(creation_time, *file.created_time());
                    assert!(creation_time <= *file.modified_time());

                    file_helper::read(c5, &file, dir.enc_key().cloned())
                })
                .then(move |res| {
                    let reader = unwrap!(res);
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

            create_test_file(client)
                .then(move |res| {
                    let (dir, file) = unwrap!(res);

                    // Update - should append (after S.E behaviour changed)
                    file_helper::write(c2, file, Mode::Append, dir.enc_key().cloned())
                        .map(move |writer| (dir, writer))
                })
                .then(move |res| {
                    let (dir, writer) = unwrap!(res);
                    writer
                        .write(&[2u8; APPEND_SIZE])
                        .and_then(move |_| writer.close())
                        .map(move |file| (dir, file))
                })
                .then(move |res| {
                    let (dir, file) = unwrap!(res);
                    file_helper::read(c3, &file, dir.enc_key().cloned())
                })
                .then(move |res| {
                    let reader = unwrap!(res);
                    let size = reader.size();
                    println!("reading {} bytes", size);
                    reader.read(0, size)
                })
                .map(move |data| {
                    assert_eq!(data.len(), ORIG_SIZE + APPEND_SIZE);
                    assert_eq!(data[0..ORIG_SIZE].to_owned(), vec![0u8; ORIG_SIZE]);
                    assert_eq!(&data[ORIG_SIZE..], [2u8; APPEND_SIZE]);
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
                    file_helper::update(c2, dir.clone(), "hello.txt", &file, 1)
                        .map(move |()| dir)
                })
                .then(move |res| {
                    let dir = unwrap!(res);

                    file_helper::fetch(c3.clone(), dir, "hello.txt")
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
                        .map(move |()| dir)
                })
                .then(move |res| {
                    let dir = unwrap!(res);
                    file_helper::fetch(c3.clone(), dir, "hello.txt")
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

    // Test deleting an entry and then re-adding it.
    // We should be able to successfully open and read the re-added file.
    #[test]
    fn file_delete_then_add() {
        random_client(|client| {
            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();
            let c5 = client.clone();
            let c6 = client.clone();

            create_test_file(client)
                .then(move |res| {
                    let (dir, file) = unwrap!(res);
                    file_helper::delete(&c2, &dir, "hello.txt", 1).map(move |_| (dir, file))
                })
                .then(move |res| {
                    let (dir, file) = unwrap!(res);

                    file_helper::write(c3, file, Mode::Overwrite, dir.enc_key().cloned())
                        .map(move |writer| (writer, dir))
                })
                .then(move |res| {
                    let (writer, dir) = unwrap!(res);

                    writer
                        .write(&[1u8; NEW_SIZE])
                        .and_then(move |_| writer.close())
                        .map(move |file| (file, dir))
                })
                .then(move |res| {
                    let (file, dir) = unwrap!(res);
                    file_helper::update(c4, dir.clone(), "hello.txt", &file, 2).map(move |_| dir)
                })
                .then(move |res| {
                    let dir = unwrap!(res);
                    file_helper::fetch(c5, dir.clone(), "hello.txt").map(
                        move |(version, file)| (version, file, dir),
                    )
                })
                .then(move |res| {
                    let (version, file, dir) = unwrap!(res);
                    assert_eq!(version, 2);
                    file_helper::read(c6, &file, dir.enc_key().cloned())
                })
                .then(move |res| {
                    let reader = unwrap!(res);
                    let size = reader.size();
                    println!("reading {} bytes", size);
                    reader.read(0, size)
                })
                .map(move |data| {
                    assert_eq!(data, vec![1u8; NEW_SIZE]);
                })
        });
    }

    // Test closing files immediately after opening them in the different modes.
    #[test]
    fn file_open_close() {
        random_client(|client| {
            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();
            let c5 = client.clone();

            create_test_file(client)
                .then(move |res| {
                    let (dir, file) = unwrap!(res);
                    // Open the file for reading
                    file_helper::read(c2, &file, dir.enc_key().cloned()).map(
                        move |reader| (reader, file, dir),
                    )
                })
                .then(move |res| {
                    // The reader should get dropped implicitly
                    let (_reader, file, dir) = unwrap!(res);
                    // Open the file for writing
                    file_helper::write(c3, file.clone(), Mode::Overwrite, dir.enc_key().cloned())
                        .map(move |writer| (writer, file, dir))
                })
                .then(move |res| {
                    let (writer, file, dir) = unwrap!(res);
                    // Close the file
                    let _ = writer.close();
                    // Open the file for appending
                    file_helper::write(c4, file.clone(), Mode::Append, dir.enc_key().cloned())
                        .map(move |writer| (writer, file, dir))
                })
                .then(move |res| {
                    let (writer, file, dir) = unwrap!(res);
                    // Close the file
                    let _ = writer.close();
                    // Open the file for reading, ensure it has original contents
                    file_helper::read(c5, &file, dir.enc_key().cloned())
                })
                .then(move |res| {
                    let reader = unwrap!(res);
                    let size = reader.size();
                    reader.read(0, size)
                })
                .map(move |data| {
                    assert_eq!(data, vec![0u8; 100]);
                })
        });
    }

    // Create and store encrypted file and make sure it can only be read back with
    // the original encryption key.
    #[test]
    fn encryption() {
        random_client(|client| {
            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();

            let mut rng = rand::thread_rng();

            let content: Vec<u8> = rng.gen_iter().take(ORIG_SIZE).collect();
            let content2 = content.clone();

            let key = shared_secretbox::gen_key();
            let wrong_key = shared_secretbox::gen_key();

            file_helper::write(
                client.clone(),
                File::new(Vec::new()),
                Mode::Overwrite,
                Some(key.clone()),
            ).then(move |res| {
                let writer = unwrap!(res);
                writer.write(&content).and_then(move |_| writer.close())
            })
                .then(move |res| {
                    // Attempt to read without an encryption key fails.
                    let file = unwrap!(res);
                    file_helper::read(c2, &file, None)
                        .and_then(|_| Err(NfsError::from("Unexpected success")))
                        .or_else(move |_error| -> Result<_, NfsError> {
                            // TODO: assert the error is of the expected variant.
                            Ok(file)
                        })
                })
                .then(move |res| {
                    // Attempt to read using incorrect encryption key fails.
                    let file = unwrap!(res);
                    file_helper::read(c3, &file, Some(wrong_key))
                        .and_then(|_| Err(NfsError::from("Unexpected success")))
                        .or_else(move |error| match error {
                            NfsError::CoreError(CoreError::SymmetricDecipherFailure) => Ok(file),
                            error => Err(error),
                        })
                })
                .then(move |res| {
                    // Attempt to read using original encryption key succeeds.
                    let file = unwrap!(res);
                    file_helper::read(c4, &file, Some(key))
                })
                .then(move |res| {
                    let reader = unwrap!(res);
                    let size = reader.size();
                    reader.read(0, size)
                })
                .then(move |res| -> Result<_, NfsError> {
                    let retrieved_content = unwrap!(res);
                    assert_eq!(retrieved_content, content2);
                    Ok(())
                })
        })
    }
}
