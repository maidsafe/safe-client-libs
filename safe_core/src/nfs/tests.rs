use DIR_TAG;
use client::{Client, MDataInfo};
use crypto::shared_secretbox;
use errors::CoreError;
use futures::Future;
use futures::future::{self, Loop};
use nfs::{File, Mode, NfsError, NfsFuture, create_dir, file_helper};
use nfs::reader::Reader;
use rand::{self, Rng};
use utils::FutureExt;
use utils::test_utils::random_client;

const APPEND_SIZE: usize = 10;
const ORIG_SIZE: usize = 5555;
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

            file_helper::insert(c3, root2.clone(), "hello.txt", &file).map(move |_| (root2, file))
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
                assert_eq!(data, vec![0u8; ORIG_SIZE]);
            })
    });
}

// Test reading file in chunks.
#[test]
fn file_read_chunks() {
    const CHUNK_SIZE: u64 = 1000;

    random_client(|client| {
        let c2 = client.clone();

        create_test_file(client)
            .then(move |res| {
                let (dir, file) = unwrap!(res);

                file_helper::read(c2, &file, dir.enc_key().cloned())
            })
            .then(|res| {
                let reader = unwrap!(res);
                let size = reader.size();
                assert_eq!(size, ORIG_SIZE as u64);

                let size_read = 0;
                let result = Vec::new();

                // Read chunks in a loop
                future::loop_fn((reader, size_read, result), move |(reader,
                       mut size_read,
                       mut result)| {
                    let to_read = if size_read + CHUNK_SIZE >= size {
                        size - size_read
                    } else {
                        CHUNK_SIZE
                    };
                    println!("reading {} bytes", to_read);
                    reader.read(size_read, to_read).then(move |res| {
                        let mut data = unwrap!(res);
                        println!("finished reading {} bytes", data.len());

                        size_read += data.len() as u64;
                        result.append(&mut data);

                        if size_read < size {
                            Ok(Loop::Continue((reader, size_read, result)))
                        } else {
                            Ok(Loop::Break((reader, size_read, result)))
                        }
                    })
                }).then(move |res: Result<(Reader<()>, u64, Vec<u8>), NfsError>| {
                    let (reader, size_read, result) = unwrap!(res);

                    assert_eq!(size, size_read);
                    assert_eq!(result, vec![0u8; ORIG_SIZE]);

                    // Read 0 bytes, should succeed
                    println!("reading 0 bytes");
                    reader.read(size, 0).map(move |data| (reader, size, data))
                })
                    .then(|res| {
                        let (reader, size, data) = unwrap!(res);
                        assert_eq!(data, Vec::<u8>::new());
                        println!("finishing reading 0 bytes");

                        // Read past the end of the file, expect an error
                        reader.read(size, 1)
                    })
                    .then(|res| -> Result<_, CoreError> {
                        match res {
                            Ok(_) => {
                                // We expect an error in this case
                                panic!("Read past end of file successfully")
                            }
                            Err(_) => Ok(()),
                        }
                    })
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
                assert_eq!(data, vec![0u8; ORIG_SIZE]);
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
