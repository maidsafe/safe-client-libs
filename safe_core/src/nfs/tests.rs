// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::btree_map;
use crate::client::{core_client::CoreClient, MDataInfo};
use crate::crypto::shared_secretbox;
use crate::errors::CoreError;
use crate::nfs::{
    create_directory,
    file_helper::{self, Version},
    File, Mode, NfsError,
};
use crate::utils::{self, generate_random_vector, test_utils::random_client};
use crate::DIR_TAG;
use log::trace;
use safe_nd::{Error as SndError, MDataKind};
use self_encryption::MIN_CHUNK_SIZE;
use tokio::{sync::mpsc, task::LocalSet};

use unwrap::unwrap;

const APPEND_SIZE: usize = 10;
const ORIG_SIZE: usize = 5555;
const NEW_SIZE: usize = 50;

async fn create_test_file_with_size(
    client: &CoreClient,
    published: bool,
    size: usize,
) -> Result<(MDataInfo, File), NfsError> {
    let c2 = client.clone();
    let c3 = client.clone();
    let root = unwrap!(MDataInfo::random_private(MDataKind::Seq, DIR_TAG));
    let root2 = root.clone();

    let res = create_directory(&client.clone(), &root, btree_map![], btree_map![]).await;
    assert!(res.is_ok());

    let writer = file_helper::write(
        c2.clone(),
        File::new(Vec::new(), published),
        Mode::Overwrite,
        root.enc_key().cloned(),
    )
    .await?;

    let bytes = vec![0u8; size];
    writer.write(&bytes).await?;
    let file = writer.close().await?;

    let _ = file_helper::insert(c3, root2.clone(), "hello.txt", &file).await;

    Ok((root2, file))
}

async fn create_test_file(
    client: &CoreClient,
    published: bool,
) -> Result<(MDataInfo, File), NfsError> {
    create_test_file_with_size(client, published, ORIG_SIZE).await
}

// Test inserting files to, and fetching from, a public mdata.
// 1. Create a private mdata with random bytes in `enc_info` and `new_enc_info`.
// 2. Create a directory for the mdata.
// 3. Insert a file with an empty filename.
// 4. Immediately fetch it back and check the contents.
// 5. Sleep several seconds and repeat step 3.
#[tokio::test]
async fn file_fetch_public_md() -> Result<(), NfsError> {
    let client: CoreClient = random_client()?;
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();
    let c5 = client.clone();
    let c6 = client.clone();
    let c7 = client.clone();

    let mut root = unwrap!(MDataInfo::random_public(MDataKind::Unseq, DIR_TAG));
    root.enc_info = Some((shared_secretbox::gen_key(), utils::generate_nonce()));
    root.new_enc_info = Some((shared_secretbox::gen_key(), utils::generate_nonce()));
    let root2 = root.clone();

    create_directory(&client, &root, btree_map![], btree_map![]).await?;
    let writer = file_helper::write(
        c2.clone(),
        File::new(Vec::new(), true),
        Mode::Overwrite,
        root.enc_key().cloned(),
    )
    .await?;

    writer.write(&[0u8; ORIG_SIZE]).await?;

    let file = writer.close().await?;

    file_helper::insert(c3, root2.clone(), "", &file).await?;
    let dir = root2;
    let (_version, file) = file_helper::fetch(c4, dir.clone(), "").await?;

    let reader = file_helper::read(c5, &file, dir.enc_key().cloned()).await?;
    let size = reader.size().await;
    trace!("reading {} bytes", size);
    let data = reader.read(0, size).await?;
    assert_eq!(data, vec![0u8; ORIG_SIZE]);

    std::thread::sleep(std::time::Duration::new(3, 0));

    let (_version, file) = file_helper::fetch(c6, dir.clone(), "").await?;

    let reader = file_helper::read(c7, &file, dir.enc_key().cloned()).await?;
    let size = reader.size().await;
    trace!("reading {} bytes", size);
    let data = reader.read(0, size).await?;
    assert_eq!(data, vec![0u8; ORIG_SIZE]);

    Ok(())
}

// Test inserting files to, and fetching from, a public mdata.
// Insert a file as Unpublished Immutable data and verify that it can be fetched.
// Other clients should not be able to fetch the file.
// After deletion the file should not be accessible anymore.
#[tokio::test]
async fn files_stored_in_unpublished_idata() -> Result<(), NfsError> {
    let (mut client1_tx, mut client1_rx) = mpsc::channel(1);
    let (mut client2_tx, mut client2_rx) = mpsc::channel(1);
    let (mut finish_tx, mut finish_rx) = mpsc::channel(1);

    // Run the local task set (we need this to run a task with !Send data).
    let local = LocalSet::new();
    let _join_handle1 = local.spawn_local(async move {
        let client: CoreClient = random_client()?;
        let c2 = client.clone();
        let c3 = client.clone();
        let c4 = client.clone();
        let c5 = client.clone();
        let c6 = client.clone();
        let c7 = client.clone();

        let root = unwrap!(MDataInfo::random_public(MDataKind::Unseq, DIR_TAG));

        create_directory(&client, &root, btree_map![], btree_map![]).await?;

        let writer =
            file_helper::write(c2, File::new(Vec::new(), false), Mode::Overwrite, None).await?;
        writer.write(&[0u8; ORIG_SIZE]).await?;
        let file = writer.close().await?;

        file_helper::insert(c3, root.clone(), "", &file).await?;
        let (_version, file) = file_helper::fetch(c4, root.clone(), "").await?;
        let reader = file_helper::read(c5, &file, None).await?;
        let size = reader.size().await;
        trace!("reading {} bytes", size);
        let data = reader.read(0, size).await?;
        assert_eq!(data, vec![0u8; ORIG_SIZE]);

        // Send the directory name for another client
        unwrap!(client1_tx.send(root.clone()).await);

        // Wait for the other client to finish it's attempt to read
        unwrap!(client2_rx.recv().await);
        let _ = file_helper::delete(c6, root.clone(), "", false, Version::Custom(1)).await?;
        let res = file_helper::fetch(c7, root, "").await;
        match res {
            Err(NfsError::FileNotFound) => (),
            Ok(_) => panic!("Unexpected success"),
            Err(e) => panic!("Unexpected error {:?}", e),
        }

        unwrap!(finish_tx.send(()).await);
        Ok::<_, NfsError>(())
    });

    let _join_handle2 = local.spawn_local(async move {
        // Get the directory name and try to fetch a file from it
        let dir: MDataInfo = unwrap!(client1_rx.recv().await);
        let client: CoreClient = random_client()?;
        let res = file_helper::fetch(client.clone(), dir, "").await;
        match res {
            Ok(_) => panic!("Unexpected success"),
            Err(NfsError::CoreError(CoreError::DataError(SndError::AccessDenied))) => (),
            Err(err) => panic!("Unexpected error: {:?}", err),
        }

        // Send a signal to the first client to continue
        unwrap!(client2_tx.send(()).await);
        unwrap!(finish_rx.recv().await);
        Ok::<_, NfsError>(())
    });

    local.await;

    Ok(())
}

// Create a file and open it for reading.
// Additionally test that the created and modified timestamps are correct.
#[tokio::test]
async fn file_read() -> Result<(), NfsError> {
    let client: CoreClient = random_client()?;
    let c2 = client.clone();

    let (dir, file) = create_test_file(&client, true).await?;
    let creation_time = *file.created_time();

    let reader = file_helper::read(c2, &file, dir.enc_key().cloned()).await?;
    let size = reader.size().await;
    trace!("reading {} bytes", size);
    let data = reader.read(0, size).await?;

    assert_eq!(creation_time, *file.created_time());
    assert!(creation_time <= *file.modified_time());
    assert_eq!(data, vec![0u8; ORIG_SIZE]);

    Ok(())
}

// Test reading file in chunks.
#[tokio::test]
async fn file_read_chunks() -> Result<(), NfsError> {
    const CHUNK_SIZE: u64 = 1000;

    let client: CoreClient = random_client()?;
    let c2 = client.clone();

    let (dir, file) = create_test_file(&client, true).await?;

    let reader = file_helper::read(c2, &file, dir.enc_key().cloned()).await?;
    let size = reader.size().await;
    assert_eq!(size, ORIG_SIZE as u64);

    let mut size_read = 0;
    let mut result = Vec::new();

    let mut done_looping = false;

    while !done_looping {
        let to_read = if size_read + CHUNK_SIZE >= size {
            size - size_read
        } else {
            CHUNK_SIZE
        };
        trace!("reading {} bytes", to_read);
        let mut data = reader.read(size_read, to_read).await?;

        size_read += data.len() as u64;
        result.append(&mut data);

        if size_read < size {
        } else {
            done_looping = true;
        }
    }
    // Read chunks in a loop

    assert_eq!(size, size_read);
    assert_eq!(result, vec![0u8; ORIG_SIZE]);

    // Read 0 bytes, should succeed
    trace!("reading 0 bytes");
    let data = reader.read(size, 0).await?;
    assert_eq!(data, Vec::<u8>::new());

    // Read past the end of the file, expect an error
    match reader.read(size, 1).await {
        Ok(_) => {
            // We expect an error in this case
            panic!("Read past end of file successfully")
        }
        Err(_) => Ok(()),
    }
}

// Test writing to files in chunks.
#[tokio::test]
async fn file_write_chunks() -> Result<(), NfsError> {
    const CHUNK_SIZE: usize = 1000;
    const GOAL_SIZE: usize = 5555;
    let content = [0u8; GOAL_SIZE];

    let client: CoreClient = random_client()?;
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();

    let (dir, file) = create_test_file(&client, true).await?;

    let writer = file_helper::write(c2, file, Mode::Overwrite, dir.enc_key().cloned()).await?;

    let mut size_written = 0;

    let mut done_looping = false;

    while !done_looping {
        let to_write = if size_written + CHUNK_SIZE >= GOAL_SIZE {
            GOAL_SIZE - size_written
        } else {
            CHUNK_SIZE
        };
        trace!("writing {} bytes", to_write);

        writer
            .write(&content[size_written..size_written + to_write])
            .await?;
        size_written += to_write;
        if size_written < GOAL_SIZE {
        } else {
            done_looping = true
        }
    }

    // Write 0 bytes, should succeed
    writer.write(&content[GOAL_SIZE..GOAL_SIZE]).await?;
    let file = writer.close().await?;
    // Updating file - append

    let writer = file_helper::write(c3, file, Mode::Append, dir.enc_key().cloned()).await?;

    let mut size_written = 0;

    let mut done_looping_again = false;

    while !done_looping_again {
        let to_write = if size_written + CHUNK_SIZE >= GOAL_SIZE {
            GOAL_SIZE - size_written
        } else {
            CHUNK_SIZE
        };
        trace!("writing {} bytes", to_write);

        writer
            .write(&content[size_written..size_written + to_write])
            .await?;

        size_written += to_write;
        if size_written < GOAL_SIZE {
        } else {
            done_looping_again = true;
        }
    }
    // Write 0 bytes, should succeed
    writer.write(&content[GOAL_SIZE..GOAL_SIZE]).await?;
    let file = writer.close().await?;

    let reader = file_helper::read(c4, &file, dir.enc_key().cloned()).await?;
    let size = reader.size().await;

    assert_eq!(size, 2 * GOAL_SIZE as u64);
    let data = reader.read(0, size).await?;
    assert_eq!(data, vec![0u8; 2 * GOAL_SIZE]);

    Ok(())
}

// Test writing to a file in Overwrite mode.
// Additionally test that the created and modified timestamps are correct.
#[tokio::test]
async fn file_update_overwrite() -> Result<(), NfsError> {
    let client: CoreClient = random_client()?;
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();
    let c5 = client.clone();

    let (dir, file) = create_test_file(&client, true).await?;
    let creation_time = *file.created_time();

    let writer = file_helper::write(c2, file, Mode::Overwrite, dir.enc_key().cloned()).await?;
    writer.write(&[1u8; NEW_SIZE]).await?;

    let file = writer.close().await?;
    let _ = file_helper::update(c3, dir.clone(), "hello.txt", &file, Version::Custom(1)).await?;
    let (_version, file) = file_helper::fetch(c4, dir.clone(), "hello.txt").await?;
    // Check file timestamps
    assert_eq!(creation_time, *file.created_time());
    assert!(creation_time <= *file.modified_time());

    let reader = file_helper::read(c5, &file, dir.enc_key().cloned()).await?;
    let size = reader.size().await;
    trace!("reading {} bytes", size);
    let data = reader.read(0, size).await?;
    assert_eq!(data, vec![1u8; NEW_SIZE]);

    Ok(())
}

#[tokio::test]
async fn file_update_append() -> Result<(), NfsError> {
    let client: CoreClient = random_client()?;

    for i in 0..3 {
        let c2 = client.clone();
        let c3 = client.clone();

        let creation_size = i * MIN_CHUNK_SIZE as usize;
        trace!("Testing with size {}", creation_size);

        let (dir, file) = create_test_file_with_size(&client, true, creation_size).await?;

        let writer = file_helper::write(c2, file, Mode::Append, dir.enc_key().cloned()).await?;
        writer.write(&[2u8; APPEND_SIZE]).await?;
        let file = writer.close().await?;
        let reader = file_helper::read(c3, &file, dir.enc_key().cloned()).await?;
        let size = reader.size().await;
        trace!("reading {} bytes", size);
        let data = reader.read(0, size).await?;
        assert_eq!(data.len(), creation_size + APPEND_SIZE);
        assert_eq!(data[0..creation_size].to_owned(), vec![0u8; creation_size]);
        assert_eq!(&data[creation_size..], [2u8; APPEND_SIZE]);
    }

    Ok(())
}

#[tokio::test]
async fn file_update_metadata() -> Result<(), NfsError> {
    let client: CoreClient = random_client()?;
    let c2 = client.clone();
    let c3 = client.clone();

    let (dir, mut file) = create_test_file(&client, true).await?;

    file.set_user_metadata(vec![12u8; 10]);
    let version =
        file_helper::update(c2, dir.clone(), "hello.txt", &file, Version::GetNext).await?;
    assert_eq!(version, 1);
    let (_version, file) = file_helper::fetch(c3, dir, "hello.txt").await?;
    assert_eq!(*file.user_metadata(), [12u8; 10][..]);
    Ok(())
}
#[tokio::test]
async fn file_delete() -> Result<(), NfsError> {
    let client: CoreClient = random_client()?;
    let c2 = client.clone();
    let c3 = client.clone();

    let (dir, _file) = create_test_file(&client, true).await?;
    let version =
        file_helper::delete(c2, dir.clone(), "hello.txt", true, Version::Custom(1)).await?;
    assert_eq!(version, 1);
    let res = file_helper::fetch(c3, dir, "hello.txt").await;
    match res {
        Ok(_) => {
            // We expect an error in this case
            panic!("Fetched non-existing file succesfully")
        }
        Err(_) => Ok(()),
    }
}

// Test deleting an entry and then re-adding it.
// We should be able to successfully open and read the re-added file.
#[tokio::test]
async fn file_delete_then_add() -> Result<(), NfsError> {
    let client: CoreClient = random_client()?;
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();
    let c5 = client.clone();
    let c6 = client.clone();

    let (dir, file) = create_test_file(&client, true).await?;
    let _ = file_helper::delete(c2, dir.clone(), "hello.txt", true, Version::Custom(1)).await?;

    let writer = file_helper::write(c3, file, Mode::Overwrite, dir.enc_key().cloned()).await?;

    writer.write(&[1u8; NEW_SIZE]).await?;
    let file = writer.close().await?;
    file_helper::insert(c4, dir.clone(), "hello.txt", &file).await?;
    let (version, file) = file_helper::fetch(c5, dir.clone(), "hello.txt").await?;
    assert_eq!(version, 0);
    let reader = file_helper::read(c6, &file, dir.enc_key().cloned()).await?;
    let size = reader.size().await;
    trace!("reading {} bytes", size);
    let data = reader.read(0, size).await?;
    assert_eq!(data, vec![1u8; NEW_SIZE]);

    Ok(())
}

// Test closing files immediately after opening them in the different modes.
#[tokio::test]
async fn file_open_close() -> Result<(), NfsError> {
    let client: CoreClient = random_client()?;
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();
    let c5 = client.clone();

    let (dir, file) = create_test_file(&client, true).await?;
    // Open the file for reading
    let _reader = file_helper::read(c2, &file, dir.enc_key().cloned()).await?;

    // Open the file for writing
    let writer =
        file_helper::write(c3, file.clone(), Mode::Overwrite, dir.enc_key().cloned()).await?;

    // Close the file
    let _ = writer.close().await?;
    // Open the file for appending
    let writer = file_helper::write(c4, file.clone(), Mode::Append, dir.enc_key().cloned()).await?;
    // Close the file
    let _ = writer.close();
    // Open the file for reading, ensure it has original contents
    let reader = file_helper::read(c5, &file, dir.enc_key().cloned()).await?;
    let size = reader.size().await;
    let data = reader.read(0, size).await?;
    assert_eq!(data, vec![0u8; ORIG_SIZE]);

    Ok(())
}

// Test opening the same file multiple times concurrently.
#[tokio::test]
async fn file_open_concurrent() -> Result<(), NfsError> {
    let client: CoreClient = random_client()?;

    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();
    let c5 = client.clone();
    let c6 = client.clone();

    let (dir, file) = create_test_file(&client, true).await?;
    // Open the first writer.
    let writer1 =
        file_helper::write(c2, file.clone(), Mode::Overwrite, dir.enc_key().cloned()).await?;

    // Open the second writer concurrently.
    let writer2 =
        file_helper::write(c3, file.clone(), Mode::Overwrite, dir.enc_key().cloned()).await?;

    // Open a reader concurrently.
    let reader = file_helper::read(c4, &file, dir.enc_key().cloned()).await?;

    // Write with the first writer.
    writer1.write(&[1u8; NEW_SIZE]).await?;
    let _ = writer1.close().await?;

    // Write with the second writer.
    writer2.write(&[2u8; NEW_SIZE]).await?;
    let file2 = writer2.close().await?;

    // Read with the reader, it should have neither of the written changes.
    let size = reader.size().await;
    let data = reader.read(0, size).await?;
    assert_eq!(data, vec![0u8; ORIG_SIZE]);

    // Open the original file for reading again, it should be unchanged.
    let reader = file_helper::read(c5, &file, dir.enc_key().cloned()).await?;

    let size = reader.size().await;
    let data = reader.read(0, size).await?;
    assert_eq!(data, vec![0u8; ORIG_SIZE]);

    // Open the file written by writer2.
    let reader = file_helper::read(c6, &file2, dir.enc_key().cloned()).await?;

    let size = reader.size().await;
    let data = reader.read(0, size).await?;

    assert_eq!(data, vec![2u8; NEW_SIZE]);

    Ok(())
}

// Create and store encrypted file and make sure it can only be read back with
// the original encryption key.
#[tokio::test]
async fn encryption() -> Result<(), NfsError> {
    let client = random_client()?;
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();

    let content: Vec<u8> = unwrap!(generate_random_vector(ORIG_SIZE));
    let content2 = content.clone();

    let key = shared_secretbox::gen_key();
    let wrong_key = shared_secretbox::gen_key();

    let writer = file_helper::write(
        client.clone(),
        File::new(Vec::new(), true),
        Mode::Overwrite,
        Some(key.clone()),
    )
    .await?;

    writer.write(&content).await?;
    let file = writer.close().await?;
    // Attempt to read without an encryption key fails.
    let _: Result<_, NfsError> = match file_helper::read(c2, &file, None).await {
        Ok(_) => return Err(NfsError::from("Unexpected success")),
        Err(_) => {
            // we want an error so do nothing
            Ok(())
        }
    };
    // Attempt to read using incorrect encryption key fails.
    // let file = unwrap!(res);
    match file_helper::read(c3, &file, Some(wrong_key)).await {
        Ok(_) => return Err(NfsError::from("Unexpected success")),
        Err(error) => match error {
            NfsError::CoreError(CoreError::SymmetricDecipherFailure) => Ok(()),
            error => Err(error),
        },
    }?;

    // Attempt to read using original encryption key succeeds.

    // should work this time.
    let reader = file_helper::read(c4, &file, Some(key)).await?;

    let size = reader.size().await;
    let retrieved_content = reader.read(0, size).await?;

    assert_eq!(retrieved_content, content2);
    Ok(())
}
