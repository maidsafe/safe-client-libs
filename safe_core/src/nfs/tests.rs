// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::core_client::CoreClient;
use crate::client::MDataInfo;
use crate::crypto::shared_secretbox;
use crate::errors::CoreError;
use crate::nfs::file_helper::{self, Version};
use crate::nfs::reader::Reader;
use crate::nfs::writer::Writer;
use crate::nfs::{create_dir, File, Mode, NfsError, NfsFuture};
use crate::utils::test_utils::random_client;
use crate::utils::FutureExt;
use crate::DIR_TAG;
use futures::future::{self, Loop};
use futures::Future;
use rand::{self, Rng};
use rust_sodium::crypto::secretbox;
use safe_nd::{Error as SndError, MDataKind};
use self_encryption::MIN_CHUNK_SIZE;
use std;
use std::sync::mpsc;
use std::thread;

const APPEND_SIZE: usize = 10;
const ORIG_SIZE: usize = 5555;
const NEW_SIZE: usize = 50;

fn create_test_file_with_size(
    client: &CoreClient,
    published: bool,
    size: usize,
) -> Box<NfsFuture<(MDataInfo, File)>> {
    let c2 = client.clone();
    let c3 = client.clone();
    let root = unwrap!(MDataInfo::random_private(MDataKind::Seq, DIR_TAG));
    let root2 = root.clone();

    create_dir(client, &root, btree_map![], btree_map![])
        .then(move |res| {
            assert!(res.is_ok());

            file_helper::write(
                c2.clone(),
                File::new(Vec::new(), published),
                Mode::Overwrite,
                root.enc_key().cloned(),
            )
        })
        .then(move |res| {
            let writer = unwrap!(res);

            let bytes = vec![0u8; size];
            writer.write(&bytes).and_then(move |_| writer.close())
        })
        .then(move |res| {
            let file = unwrap!(res);

            file_helper::insert(c3, root2.clone(), "hello.txt", &file).map(move |_| (root2, file))
        })
        .into_box()
}

fn create_test_file(client: &CoreClient, published: bool) -> Box<NfsFuture<(MDataInfo, File)>> {
    create_test_file_with_size(client, published, ORIG_SIZE)
}

// Test inserting files to, and fetching from, a public mdata.
// 1. Create a private mdata with random bytes in `enc_info` and `new_enc_info`.
// 2. Create a directory for the mdata.
// 3. Insert a file with an empty filename.
// 4. Immediately fetch it back and check the contents.
// 5. Sleep several seconds and repeat step 3.
#[test]
fn file_fetch_public_md() {
    random_client(|client| {
        let c2 = client.clone();
        let c3 = client.clone();
        let c4 = client.clone();
        let c5 = client.clone();
        let c6 = client.clone();
        let c7 = client.clone();

        let mut root = unwrap!(MDataInfo::random_public(MDataKind::Unseq, DIR_TAG));
        root.enc_info = Some((shared_secretbox::gen_key(), secretbox::gen_nonce()));
        root.new_enc_info = Some((shared_secretbox::gen_key(), secretbox::gen_nonce()));
        let root2 = root.clone();

        create_dir(client, &root, btree_map![], btree_map![])
            .then(move |res| {
                assert!(res.is_ok());

                file_helper::write(
                    c2.clone(),
                    File::new(Vec::new(), true),
                    Mode::Overwrite,
                    root.enc_key().cloned(),
                )
            })
            .then(move |res| {
                let writer = unwrap!(res);

                writer
                    .write(&[0u8; ORIG_SIZE])
                    .and_then(move |_| writer.close())
            })
            .then(move |res| {
                let file = unwrap!(res);

                file_helper::insert(c3, root2.clone(), "", &file).map(move |_| root2)
            })
            .then(move |res| {
                let dir = unwrap!(res);

                file_helper::fetch(c4, dir.clone(), "").map(move |(_version, file)| (dir, file))
            })
            .then(move |res| {
                let (dir, file) = unwrap!(res);

                file_helper::read(c5, &file, dir.enc_key().cloned())
                    .map(move |reader| (reader, dir))
            })
            .then(move |res| {
                let (reader, dir) = unwrap!(res);
                let size = reader.size();
                trace!("reading {} bytes", size);
                reader.read(0, size).map(move |data| {
                    assert_eq!(data, vec![0u8; ORIG_SIZE]);
                    dir
                })
            })
            .then(move |res| {
                let dir = unwrap!(res);

                std::thread::sleep(std::time::Duration::new(3, 0));

                file_helper::fetch(c6, dir.clone(), "").map(move |(_version, file)| (dir, file))
            })
            .then(move |res| {
                let (dir, file) = unwrap!(res);

                file_helper::read(c7, &file, dir.enc_key().cloned())
                    .map(move |reader| (reader, dir))
            })
            .then(move |res| {
                let (reader, _dir) = unwrap!(res);
                let size = reader.size();
                trace!("reading {} bytes", size);
                reader.read(0, size).map(move |data| {
                    assert_eq!(data, vec![0u8; ORIG_SIZE]);
                })
            })
    });
}

// Test inserting files to, and fetching from, a public mdata.
// Insert a file as Unpublished Immutable data and verify that it can be fetched.
// Other clients should not be able to fetch the file.
// After deletion the file should not be accessible anymore.
#[allow(unsafe_code)]
#[test]
fn files_stored_in_unpublished_idata() {
    let (client1_tx, client1_rx) = mpsc::channel();
    let (client2_tx, client2_rx) = mpsc::channel();
    let (finish_tx, finish_rx) = mpsc::channel();
    let _joiner = thread::spawn(|| {
        random_client(|client| {
            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();
            let c5 = client.clone();
            let c6 = client.clone();
            let c7 = client.clone();

            let root = unwrap!(MDataInfo::random_public(MDataKind::Unseq, DIR_TAG));
            let root2 = root.clone();

            create_dir(client, &root, btree_map![], btree_map![])
                .and_then(move |()| {
                    file_helper::write(
                        c2.clone(),
                        File::new(Vec::new(), false),
                        Mode::Overwrite,
                        None,
                    )
                })
                .and_then(move |writer| {
                    writer
                        .write(&[0u8; ORIG_SIZE])
                        .and_then(move |_| writer.close())
                })
                .and_then(move |file| {
                    file_helper::insert(c3, root2.clone(), "", &file).map(move |_| root2)
                })
                .and_then(move |dir| {
                    file_helper::fetch(c4, dir.clone(), "").map(move |(_version, file)| (dir, file))
                })
                .and_then(move |(dir, file)| {
                    file_helper::read(c5, &file, None).map(move |reader| (reader, dir))
                })
                .and_then(move |(reader, dir)| {
                    let size = reader.size();
                    trace!("reading {} bytes", size);
                    reader.read(0, size).map(move |data| {
                        assert_eq!(data, vec![0u8; ORIG_SIZE]);
                        dir
                    })
                })
                .and_then(move |dir| {
                    // Send the directory name for another client
                    unwrap!(client1_tx.send(dir.clone()));

                    // Wait for the other client to finish it's attempt to read
                    unwrap!(client2_rx.recv());
                    file_helper::delete(c6, dir.clone(), "", false, Version::Custom(1)).map(|_| dir)
                })
                .and_then(move |dir| file_helper::fetch(c7, dir.clone(), ""))
                .then(move |res| {
                    match res {
                        Err(NfsError::FileNotFound) => (),
                        Ok(_) => panic!("Unexpected success"),
                        Err(e) => panic!("Unexpected error {:?}", e),
                    }
                    unwrap!(finish_tx.send(()));
                    Ok::<_, CoreError>(())
                })
        });
    });

    // Get the directory name and try to fetch a file from it
    let dir: MDataInfo = unwrap!(client1_rx.recv());
    random_client(move |client| {
        file_helper::fetch(client.clone(), dir.clone(), "").then(|res| {
            match res {
                Ok(_) => panic!("Unexpected success"),
                Err(NfsError::CoreError(CoreError::DataError(SndError::AccessDenied))) => (),
                Err(err) => panic!("Unexpected error: {:?}", err),
            }
            Ok::<_, CoreError>(())
        })
    });
    // Send a signal to the first client to continue
    unwrap!(client2_tx.send(()));
    unwrap!(finish_rx.recv());
}

// Create a file and open it for reading.
// Additionally test that the created and modified timestamps are correct.
#[test]
fn file_read() {
    random_client(|client| {
        let c2 = client.clone();

        create_test_file(client, true)
            .then(move |res| {
                let (dir, file) = unwrap!(res);
                let creation_time = *file.created_time();

                file_helper::read(c2, &file, dir.enc_key().cloned())
                    .map(move |reader| (reader, file, creation_time))
            })
            .then(|res| {
                let (reader, file, creation_time) = unwrap!(res);
                let size = reader.size();
                trace!("reading {} bytes", size);
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

        create_test_file(client, true)
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
                future::loop_fn(
                    (reader, size_read, result),
                    move |(reader, mut size_read, mut result)| {
                        let to_read = if size_read + CHUNK_SIZE >= size {
                            size - size_read
                        } else {
                            CHUNK_SIZE
                        };
                        trace!("reading {} bytes", to_read);
                        reader.read(size_read, to_read).then(move |res| {
                            let mut data = unwrap!(res);

                            size_read += data.len() as u64;
                            result.append(&mut data);

                            if size_read < size {
                                Ok(Loop::Continue((reader, size_read, result)))
                            } else {
                                Ok(Loop::Break((reader, size_read, result)))
                            }
                        })
                    },
                )
                .then(
                    move |res: Result<(Reader<CoreClient>, u64, Vec<u8>), NfsError>| {
                        let (reader, size_read, result) = unwrap!(res);

                        assert_eq!(size, size_read);
                        assert_eq!(result, vec![0u8; ORIG_SIZE]);

                        // Read 0 bytes, should succeed
                        trace!("reading 0 bytes");
                        reader.read(size, 0).map(move |data| (reader, size, data))
                    },
                )
                .then(|res| {
                    let (reader, size, data) = unwrap!(res);
                    assert_eq!(data, Vec::<u8>::new());

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

// Test writing to files in chunks.
#[test]
fn file_write_chunks() {
    const CHUNK_SIZE: usize = 1000;
    const GOAL_SIZE: usize = 5555;
    let content = [0u8; GOAL_SIZE];

    random_client(move |client| {
        let c2 = client.clone();
        let c3 = client.clone();
        let c4 = client.clone();

        create_test_file(client, true)
            .then(move |res| {
                // Updating file - overwrite
                let (dir, file) = unwrap!(res);

                file_helper::write(c2, file, Mode::Overwrite, dir.enc_key().cloned())
                    .map(move |writer| (writer, dir))
            })
            .then(move |res| {
                let (writer, dir) = unwrap!(res);

                let size_written = 0;
                future::loop_fn((writer, size_written), move |(writer, mut size_written)| {
                    let to_write = if size_written + CHUNK_SIZE >= GOAL_SIZE {
                        GOAL_SIZE - size_written
                    } else {
                        CHUNK_SIZE
                    };
                    trace!("writing {} bytes", to_write);

                    writer
                        .write(&content[size_written..size_written + to_write])
                        .then(move |res| {
                            unwrap!(res);

                            size_written += to_write;
                            if size_written < GOAL_SIZE {
                                Ok(Loop::Continue((writer, size_written)))
                            } else {
                                Ok(Loop::Break(writer))
                            }
                        })
                })
                .map(move |writer| (writer, dir))
            })
            .then(
                move |res: Result<(Writer<CoreClient>, MDataInfo), NfsError>| {
                    let (writer, dir) = unwrap!(res);
                    // Write 0 bytes, should succeed
                    writer
                        .write(&content[GOAL_SIZE..GOAL_SIZE])
                        .map(move |_| (writer, dir))
                },
            )
            .then(move |res| {
                let (writer, dir) = unwrap!(res);
                writer.close().map(move |file| (file, dir))
            })
            .then(move |res| {
                // Updating file - append
                let (file, dir) = unwrap!(res);

                file_helper::write(c3, file, Mode::Append, dir.enc_key().cloned())
                    .map(move |writer| (writer, dir))
            })
            .then(move |res| {
                let (writer, dir) = unwrap!(res);

                let size_written = 0;
                future::loop_fn((writer, size_written), move |(writer, mut size_written)| {
                    let to_write = if size_written + CHUNK_SIZE >= GOAL_SIZE {
                        GOAL_SIZE - size_written
                    } else {
                        CHUNK_SIZE
                    };
                    trace!("writing {} bytes", to_write);

                    writer
                        .write(&content[size_written..size_written + to_write])
                        .then(move |res| {
                            unwrap!(res);

                            size_written += to_write;
                            if size_written < GOAL_SIZE {
                                Ok(Loop::Continue((writer, size_written)))
                            } else {
                                Ok(Loop::Break(writer))
                            }
                        })
                })
                .map(move |writer| (writer, dir))
            })
            .then(
                move |res: Result<(Writer<CoreClient>, MDataInfo), NfsError>| {
                    let (writer, dir) = unwrap!(res);
                    // Write 0 bytes, should succeed
                    writer
                        .write(&content[GOAL_SIZE..GOAL_SIZE])
                        .map(move |_| (writer, dir))
                },
            )
            .then(move |res| {
                let (writer, dir) = unwrap!(res);
                writer.close().map(move |file| (file, dir))
            })
            .then(move |res| {
                let (file, dir) = unwrap!(res);

                file_helper::read(c4, &file, dir.enc_key().cloned())
            })
            .then(move |res| {
                let reader = unwrap!(res);
                let size = reader.size();

                assert_eq!(size, 2 * GOAL_SIZE as u64);
                reader.read(0, size)
            })
            .map(move |data| {
                assert_eq!(data, vec![0u8; 2 * GOAL_SIZE]);
            })
    })
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

        create_test_file(client, true)
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
                file_helper::update(c3, dir.clone(), "hello.txt", &file, Version::Custom(1))
                    .map(move |_| (dir, creation_time))
            })
            .then(move |res| {
                let (dir, creation_time) = unwrap!(res);
                file_helper::fetch(c4, dir.clone(), "hello.txt")
                    .map(move |(_version, file)| (dir, file, creation_time))
            })
            .then(move |res| {
                let (dir, file, creation_time) = unwrap!(res);

                // Check file timestamps
                assert_eq!(creation_time, *file.created_time());
                assert!(creation_time <= *file.modified_time());

                file_helper::read(c5, &file, dir.enc_key().cloned())
            })
            .then(move |res| {
                let reader = unwrap!(res);
                let size = reader.size();
                trace!("reading {} bytes", size);
                reader.read(0, size)
            })
            .map(move |data| {
                assert_eq!(data, vec![1u8; NEW_SIZE]);
            })
    });
}

#[test]
fn file_update_append() {
    random_client(move |client| {
        let mut futures = vec![];

        for i in 0..3 {
            let c2 = client.clone();
            let c3 = client.clone();

            let size = i * MIN_CHUNK_SIZE as usize;
            trace!("Testing with size {}", size);

            futures.push(
                create_test_file_with_size(client, true, size)
                    .then(move |res| {
                        let (dir, file) = unwrap!(res);

                        // Updating file - append
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
                        trace!("reading {} bytes", size);
                        reader.read(0, size)
                    })
                    .map(move |data| {
                        assert_eq!(data.len(), size + APPEND_SIZE);
                        assert_eq!(data[0..size].to_owned(), vec![0u8; size]);
                        assert_eq!(&data[size..], [2u8; APPEND_SIZE]);
                    }),
            );
        }

        future::join_all(futures).map(|_| ())
    })
}

#[test]
fn file_update_metadata() {
    random_client(|client| {
        let c2 = client.clone();
        let c3 = client.clone();

        create_test_file(client, true)
            .then(move |res| {
                let (dir, mut file) = unwrap!(res);

                file.set_user_metadata(vec![12u8; 10]);
                file_helper::update(c2, dir.clone(), "hello.txt", &file, Version::GetNext).map(
                    move |version| {
                        assert_eq!(version, 1);
                        dir
                    },
                )
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

        create_test_file(client, true)
            .then(move |res| {
                let (dir, _file) = unwrap!(res);
                file_helper::delete(c2, dir.clone(), "hello.txt", true, Version::Custom(1)).map(
                    move |version| {
                        assert_eq!(version, 1);
                        dir
                    },
                )
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

        create_test_file(client, true)
            .then(move |res| {
                let (dir, file) = unwrap!(res);
                file_helper::delete(c2, dir.clone(), "hello.txt", true, Version::Custom(1))
                    .map(move |_| (dir, file))
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
                file_helper::insert(c4, dir.clone(), "hello.txt", &file).map(move |_| dir)
            })
            .then(move |res| {
                let dir = unwrap!(res);
                file_helper::fetch(c5, dir.clone(), "hello.txt")
                    .map(move |(version, file)| (version, file, dir))
            })
            .then(move |res| {
                let (version, file, dir) = unwrap!(res);
                assert_eq!(version, 0);
                file_helper::read(c6, &file, dir.enc_key().cloned())
            })
            .then(move |res| {
                let reader = unwrap!(res);
                let size = reader.size();
                trace!("reading {} bytes", size);
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

        create_test_file(client, true)
            .then(move |res| {
                let (dir, file) = unwrap!(res);
                // Open the file for reading
                file_helper::read(c2, &file, dir.enc_key().cloned())
                    .map(move |reader| (reader, file, dir))
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

// Test opening the same file multiple times concurrently.
#[test]
fn file_open_concurrent() {
    random_client(|client| {
        let c2 = client.clone();
        let c3 = client.clone();
        let c4 = client.clone();
        let c5 = client.clone();
        let c6 = client.clone();

        create_test_file(client, true)
            .then(move |res| {
                let (dir, file) = unwrap!(res);

                // Open the first writer.
                file_helper::write(c2, file.clone(), Mode::Overwrite, dir.enc_key().cloned())
                    .map(move |writer1| (writer1, file, dir))
            })
            .then(move |res| {
                let (writer1, file, dir) = unwrap!(res);

                // Open the second writer concurrently.
                file_helper::write(c3, file.clone(), Mode::Overwrite, dir.enc_key().cloned())
                    .map(move |writer2| (writer1, writer2, file, dir))
            })
            .then(move |res| {
                let (writer1, writer2, file, dir) = unwrap!(res);

                // Open a reader concurrently.
                file_helper::read(c4, &file, dir.enc_key().cloned())
                    .map(move |reader| (writer1, writer2, reader, file, dir))
            })
            .then(move |res| {
                let (writer1, writer2, reader, file, dir) = unwrap!(res);

                // Write with the first writer.
                writer1
                    .write(&[1u8; NEW_SIZE])
                    .and_then(move |_| writer1.close())
                    .map(move |_| (writer2, reader, file, dir))
            })
            .then(move |res| {
                let (writer2, reader, file, dir) = unwrap!(res);

                // Write with the second writer.
                writer2
                    .write(&[2u8; NEW_SIZE])
                    .and_then(move |_| writer2.close())
                    .map(move |file2| (reader, file, file2, dir))
            })
            .then(move |res| {
                let (reader, file, file2, dir) = unwrap!(res);

                // Read with the reader, it should have neither of the written changes.
                let size = reader.size();
                reader.read(0, size).map(move |data| {
                    assert_eq!(data, vec![0u8; ORIG_SIZE]);
                    (file, file2, dir)
                })
            })
            .then(move |res| {
                let (file, file2, dir) = unwrap!(res);

                // Open the original file for reading again, it should be unchanged.
                file_helper::read(c5, &file, dir.enc_key().cloned())
                    .map(|reader| (reader, file2, dir))
            })
            .then(move |res| {
                let (reader, file2, dir) = unwrap!(res);

                let size = reader.size();
                reader.read(0, size).map(move |data| {
                    assert_eq!(data, vec![0u8; ORIG_SIZE]);
                    (file2, dir)
                })
            })
            .then(move |res| {
                let (file2, dir) = unwrap!(res);

                // Open the file written by writer2.
                file_helper::read(c6, &file2, dir.enc_key().cloned())
            })
            .then(move |res| {
                let reader = unwrap!(res);

                let size = reader.size();
                reader
                    .read(0, size)
                    .map(move |data| assert_eq!(data, vec![2u8; NEW_SIZE]))
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
            File::new(Vec::new(), true),
            Mode::Overwrite,
            Some(key.clone()),
        )
        .then(move |res| {
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
