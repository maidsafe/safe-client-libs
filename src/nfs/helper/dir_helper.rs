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


use core::{Client, CoreError, FutureExt};
use core::structured_data::unversioned;
use futures::{Future, stream};
use futures::stream::Stream;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use nfs::{Dir, DirId, DirMetadata, File, NfsError, NfsFuture};
use rand;
use routing::{Data, DataIdentifier, ImmutableData, StructuredData, XorName};
use rust_sodium::crypto::secretbox;

/// Split path into tokens.
pub fn tokenise_path(path: &str) -> Vec<String> {
    path.split(|element| element == '/')
        .filter(|token| !token.is_empty())
        .map(|token| token.to_string())
        .collect()
}

/// Creates a Dir in the network. Returns DataIdentifier for the created dir.
fn create(client: Client,
          dir: &Dir,
          encryption_key: Option<&secretbox::Key>)
          -> Box<NfsFuture<DataIdentifier>> {
    trace!("Creating directory");

    let id = rand::random();
    let data_id = DataIdentifier::Structured(id, ::UNVERSIONED_STRUCT_DATA_TYPE_TAG);

    let c2 = client.clone();
    let signing_key = fry!(client.secret_signing_key());

    save(client.clone(), dir, &data_id, encryption_key)
        .and_then(move |structured_data| {
            let data_id = structured_data.identifier();

            c2.put_recover(Data::Structured(structured_data), None, signing_key)
                .map_err(NfsError::from)
                .map(move |_| data_id)
        })
        .into_box()
}

/// Adds a sub directory to a parent. Parent directory is updated and the sub
/// directory metadata returned as a result.
pub fn add_sub_dir(client: Client,
                   name: String,
                   dir_id: &DirId,
                   user_metadata: Vec<u8>,
                   parent: &mut Dir,
                   parent_id: &DirId)
                   -> Box<NfsFuture<DirMetadata>> {
    trace!("Creating directory with name: {}", name);

    let (dir_id, secret_key) = dir_id.clone();
    let metadata = DirMetadata::new(dir_id.name().clone(), name, user_metadata, secret_key);
    fry!(parent.upsert_sub_dir(metadata.clone()));

    let parent = parent.clone();

    update(client.clone(), parent_id, &parent)
        .map(move |_| metadata)
        .into_box()
}

/// Creates and adds a child directory
/// Returns (updated_parent_dir, created_dir, created_dir_metadata)
pub fn create_sub_dir<S>(client: Client,
                         name: S,
                         encrypt_key: Option<secretbox::Key>,
                         user_metadata: Vec<u8>,
                         parent: &Dir,
                         parent_id: &DirId)
                         -> Box<NfsFuture<(Dir, Dir, DirMetadata)>>
    where S: Into<String>
{
    let dir = Dir::new();
    let c2 = client.clone();
    let name = name.into();
    let mut parent = parent.clone();
    let parent_id = parent_id.clone();
    create(client.clone(), &dir, encrypt_key.as_ref())
        .and_then(move |child_id| {
            add_sub_dir(c2,
                        name,
                        &(child_id, encrypt_key),
                        user_metadata,
                        &mut parent,
                        &parent_id)
                .map(move |metadata| (parent, metadata))
        })
        .map(move |(parent, metadata)| (parent, dir, metadata))
        .into_box()
}

/// Deletes a sub directory
pub fn delete(client: Client,
              parent: &mut Dir,
              parent_id: &DirId,
              dir_to_delete: &str)
              -> Box<NfsFuture<()>> {
    trace!("Deleting directory with name: {}", dir_to_delete);

    let dir_meta = fry!(parent.remove_sub_dir(dir_to_delete));

    let c2 = client.clone();
    let c3 = client.clone();
    let parent = parent.clone();
    let parent_id = parent_id.clone();

    get_structured_data(client.clone(), &dir_meta.id().0)
        .and_then(move |sd| {
            let sign_key = fry!(c2.secret_signing_key()).clone();

            let delete_sd = fry!(StructuredData::new(sd.get_type_tag(),
                                                     *sd.name(),
                                                     sd.get_version() + 1,
                                                     vec![],
                                                     vec![],
                                                     sd.get_owner_keys().clone(),
                                                     Some(&sign_key))
                .map_err(CoreError::from));

            c2.delete_recover(Data::Structured(delete_sd), None)
                .map_err(NfsError::from)
                .into_box()
        })
        .and_then(move |_| update(c3, &parent_id, &parent))
        .into_box()
}

/// Updates an existing Directory in the network.
pub fn update(client: Client, dir_id: &DirId, directory: &Dir) -> Box<NfsFuture<()>> {
    trace!("Updating directory given the directory listing.");

    let dir_clone = directory.clone();
    let (locator, secret_key) = dir_id.clone();
    let c2 = client.clone();
    let c3 = client.clone();

    let signing_key = fry!(client.secret_signing_key());
    let owner_key = fry!(client.public_signing_key());

    get_structured_data(client.clone(), &locator)
        .and_then(move |structured_data| {
            let serialised_data = fry!(serialise(&dir_clone));

            if let DataIdentifier::Structured(id, type_tag) = locator {
                trace!("Updating directory ID {:?} with a new one.", id);

                unversioned::create(&c2,
                                    type_tag,
                                    id,
                                    structured_data.get_version() + 1,
                                    serialised_data,
                                    vec![owner_key.clone()],
                                    Vec::new(),
                                    signing_key,
                                    secret_key)
                    .map_err(NfsError::from)
                    .into_box()
            } else {
                err!(NfsError::ParameterIsNotValid)
            }
        })
        .and_then(move |updated_structured_data| {
            debug!("Posting updated structured data to the network ...");

            c3.post(Data::Structured(updated_structured_data), None)
                .map_err(NfsError::from)
        })
        .into_box()
}

/// Return the Directory
pub fn get(client: Client, dir_id: &DirId) -> Box<NfsFuture<Dir>> {
    trace!("Getting a directory.");

    let c2 = client.clone();
    let (id, sk) = dir_id.clone();

    get_structured_data(client.clone(), &id)
        .and_then(move |structured_data| {
            unversioned::extract_value(&c2, &structured_data, sk).map_err(NfsError::from)
        })
        .and_then(move |encoded| Ok(deserialise::<Dir>(&encoded)?))
        .into_box()
}

/// Returns the Root Directory
pub fn user_root_dir(client: Client) -> Box<NfsFuture<(Dir, DirId)>> {
    trace!("Getting the user root directory listing.");

    let root_directory_id = client.user_root_dir_id();

    let fut = match root_directory_id {
        Some((id, key)) => {
            get(client.clone(), &(id, key.clone()))
                .map(move |dir| (dir, (id, key)))
                .into_box()
        }
        None => {
            debug!("Root directory does not exist - creating one.");
            let c2 = client.clone();
            let key = Some(secretbox::gen_key());
            let dir = Dir::new();

            create(client.clone(), &dir, key.as_ref())
                .and_then(move |data_id| {
                    let dir_id = (data_id.clone(), key);
                    c2.set_user_root_dir_id(dir_id.clone())
                        .map_err(NfsError::from)
                        .map(move |_| (dir, dir_id))
                })
                .into_box()
        }
    };

    fut.into_box()
}

/// Returns the Configuration Directory from the configuration root folder
/// Creates the directory or the root or both if it doesn't find one.
pub fn configuration_dir(client: Client, dir_name: String) -> Box<NfsFuture<(Dir, DirMetadata)>> {
    trace!("Getting a configuration directory (from withing configuration root dir) with name: \
            {}.",
           dir_name);

    let config_dir_id = client.config_root_dir_id();

    let fut = match config_dir_id {
        Some(dir_id) => get(client.clone(), &dir_id).map(|dir| (dir_id, dir)).into_box(),
        None => {
            debug!("Configuartion Root directory does not exist - creating one.");

            let c2 = client.clone();
            let dir = Dir::new();
            let key = None;

            create(client.clone(), &dir, key)
                .and_then(move |created_id| {
                    let config_dir_id = (created_id, None);
                    c2.set_config_root_dir_id(config_dir_id.clone())
                        .map_err(NfsError::from)
                        .map(|_| (config_dir_id, dir))
                })
                .into_box()
        }
    };

    fut.and_then(move |(config_dir_id, config_dir)| {
            match config_dir.find_sub_dir(&dir_name) {
                Some(metadata) => {
                    let metadata = metadata.clone();
                    get(client.clone(), &metadata.id())
                        .map(move |cdir| (cdir, metadata))
                        .into_box()
                }
                None => {
                    debug!("Given configuration directory does not exist (inside the root \
                            configuration dir) - creating one.");

                    let cdir = config_dir.clone();

                    create_sub_dir(client.clone(),
                                   dir_name,
                                   Some(secretbox::gen_key()),
                                   Vec::new(),
                                   &cdir,
                                   &config_dir_id)
                        .map(move |(_, cdir, metadata)| (cdir, metadata))
                        .into_box()
                }
            }
        })
        .into_box()
}

/// Get file by path relative to `root_dir`.
pub fn get_file_by_path(client: &Client,
                        root_dir: Option<&DirId>,
                        path: &str)
                        -> Box<NfsFuture<File>> {
    let mut tokens = tokenise_path(path);
    let file_name = fry!(tokens.pop().ok_or(NfsError::FileNotFound));

    final_sub_dir(client, &tokens, root_dir)
        .and_then(move |(dir, _)| {
            dir.find_file(&file_name)
                .map(|file| file.clone())
                .ok_or(NfsError::FileNotFound)
        })
        .into_box()
}

/// Get directory by path relative to `root_dir`.
pub fn get_dir_by_path(client: &Client,
                       root_dir: Option<&DirId>,
                       path: &str)
                       -> Box<NfsFuture<(Dir, DirMetadata)>> {
    let tokens = tokenise_path(path);
    final_sub_dir(client, &tokens, root_dir)
}

/// Get the directory at the given tokenised path. The path is taken relative
/// to `starting_directory`, unless it is `None`, in which case it is taken
/// relative to the user root directory.
pub fn final_sub_dir(client: &Client,
                     tokens: &[String],
                     starting_directory: Option<&DirId>)
                     -> Box<NfsFuture<(Dir, DirMetadata)>> {
    trace!("Traverse directory tree to get the final subdirectory.");

    let dir_fut = match starting_directory {
        Some(dir_id) => {
            trace!("Traversal begins at given starting directory.");
            let dir_id = dir_id.clone();
            get(client.clone(), &dir_id).map(move |dir| (dir, dir_id)).into_box()
        }
        None => {
            trace!("Traversal begins at user-root-directory.");
            user_root_dir(client.clone())
        }
    };

    let tokens_iter = tokens.to_owned().into_iter().map(|el| Ok(el));
    let c2 = client.clone();

    dir_fut.and_then(move |(current_dir, start_dir_id)| {
            let (dir_id, key) = start_dir_id;
            let meta = DirMetadata::new(*dir_id.name(), "root", Vec::new(), key);

            stream::iter(tokens_iter).fold((current_dir, meta), move |(dir, _metadata), token| {
                trace!("Traversing to dir with name: {}", token);

                let metadata = fry!(dir.find_sub_dir(&token)
                        .ok_or(NfsError::DirectoryNotFound))
                    .clone();

                get(c2.clone(), &metadata.id())
                    .map(move |dir| (dir, metadata))
                    .into_box()
            })
        })
        .into_box()
}

/// Creates a StructuredData with the directory data in the Network
fn save(client: Client,
        dir: &Dir,
        locator: &DataIdentifier,
        encryption_key: Option<&secretbox::Key>)
        -> Box<NfsFuture<StructuredData>> {
    trace!("Converting directory to an unversioned StructuredData.");

    let signing_key = fry!(client.secret_signing_key());
    let owner_key = fry!(client.public_signing_key());

    let encoded = fry!(serialise(&dir));

    if let DataIdentifier::Structured(id, type_tag) = *locator {
        unversioned::create(&client,
                            type_tag,
                            id,
                            0,
                            encoded,
                            vec![owner_key.clone()],
                            Vec::new(),
                            signing_key,
                            encryption_key.cloned())
            .map_err(NfsError::from)
            .into_box()
    } else {
        err!(NfsError::ParameterIsNotValid)
    }
}

/// Saves the data as ImmutableData in the network and returns the name
#[allow(unused)]
fn save_as_immutable_data(client: Client, data: Vec<u8>) -> Box<NfsFuture<XorName>> {
    let immutable_data = ImmutableData::new(data);
    let name = *immutable_data.name();
    debug!("Posting PUT request to save immutable data to the network ...");

    client.put(Data::Immutable(immutable_data), None)
        .map(move |_| name)
        .map_err(NfsError::from)
        .into_box()
}

/// Performs a shallow copy of a provided directory (sub directories aren't
/// copied)
fn shallow_copy(client: Client,
                src: Dir,
                src_meta: DirMetadata)
                -> Box<NfsFuture<(Dir, DirMetadata)>> {
    let sk = if src_meta.encrypt_key().is_some() {
        Some(secretbox::gen_key())
    } else {
        None
    };
    create(client, &src, sk.as_ref())
        .and_then(move |dir_id| {
            let mut dst_meta = DirMetadata::new(*dir_id.name(),
                                                src_meta.name(),
                                                src_meta.user_metadata().to_owned(),
                                                sk);

            dst_meta.set_created_time(*src_meta.created_time());

            Ok((src, dst_meta))
        })
        .into_box()
}

/// Performs a full copy of a provided directory
fn deep_copy(client: Client,
             src: &Dir,
             src_meta: &DirMetadata)
             -> Box<NfsFuture<(Dir, DirMetadata)>> {
    let parent_meta = src_meta.clone();

    if src.sub_dirs().len() == 0 {
        shallow_copy(client.clone(), src.clone(), parent_meta)
    } else {
        let c2 = client.clone();
        let c3 = client.clone();

        let mut start_dir = Dir::new();
        for f in src.files() {
            let _ = start_dir.upsert_file(f.clone());
        }

        let sub_dirs = src.sub_dirs().to_owned().into_iter().map(Ok);

        stream::iter(sub_dirs)
            .fold(start_dir, move |mut parent, sub_dir| {
                let c3 = c2.clone();

                get(c2.clone(), &sub_dir.id())
                    .and_then(move |dir| deep_copy(c3, &dir, &sub_dir))
                    .and_then(move |(_dir_copy, dir_meta)| {
                        parent.upsert_sub_dir(dir_meta)
                            .map(move |_| parent)
                    })
            })
            .and_then(move |parent| shallow_copy(c3, parent, parent_meta))
            .into_box()
    }
}

/// Move or copy source directory to the provided destination dir
pub fn move_dir<S>(client: &Client,
                   retain_src: bool,
                   mut src_parent_dir: Dir,
                   src_parent_meta: DirMetadata,
                   dir_to_move: &str,
                   mut dst_dir: Dir,
                   dst_meta: DirMetadata,
                   dst_path: S)
                   -> Box<NfsFuture<()>>
    where S: Into<String>
{
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();

    let dst_path = dst_path.into();

    if retain_src {
        // Copy
        let src_meta = fry!(src_parent_dir.find_sub_dir(dir_to_move)
            .cloned()
            .ok_or(NfsError::DirectoryNotFound));

        get(c2, &src_meta.id())
            .and_then(move |src_dir| deep_copy(c3, &src_dir, &src_meta))
            .and_then(move |(_copy, mut copy_meta)| {
                copy_meta.set_name(dst_path);
                fry!(dst_dir.upsert_sub_dir(copy_meta));
                update(c4, &dst_meta.id(), &dst_dir).into_box()
            })
            .into_box()
    } else {
        // Move
        let mut moved_meta = fry!(src_parent_dir.remove_sub_dir(dir_to_move));
        moved_meta.set_name(dst_path);

        fry!(dst_dir.upsert_sub_dir(moved_meta));

        update(c2, &dst_meta.id(), &dst_dir)
            .and_then(move |_| update(c3, &src_parent_meta.id(), &src_parent_dir))
            .into_box()
    }

}

/// Get StructuredData from the Network
fn get_structured_data(client: Client, request: &DataIdentifier) -> Box<NfsFuture<StructuredData>> {
    debug!("Getting structured data from the network ...");

    let response_future = client.get(*request, None);

    let final_fut = response_future.and_then(move |result| {
        match result {
            Data::Structured(structured_data) => Ok(structured_data),
            _ => Err(CoreError::ReceivedUnexpectedData),
        }
    });

    final_fut.map_err(NfsError::from).into_box()
}

/// Get ImmutableData from the Network
#[allow(unused)]
fn get_immutable_data(client: Client, id: XorName) -> Box<NfsFuture<ImmutableData>> {
    let request = DataIdentifier::Immutable(id);
    debug!("Getting immutable data from the network ...");

    let response_future = client.get(request, None);

    let final_fut = response_future.and_then(move |result| {
        match result {
            Data::Immutable(immutable_data) => Ok(immutable_data),
            _ => Err(CoreError::ReceivedUnexpectedData),
        }
    });

    Box::new(final_fut.map_err(NfsError::from))
}

#[cfg(test)]
mod tests {
    use core::utility::test_utils::{finish, random_client};
    use futures::Future;
    use nfs::{Dir, DirMetadata};
    use nfs::helper::dir_helper;
    use rand;
    use routing::DataIdentifier;
    use std::sync::mpsc;

    #[test]
    fn create_dir() {
        random_client(|client| {
            // Create a Directory
            let mut dir = Dir::new();
            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();
            let c5 = client.clone();
            let c6 = client.clone();

            let sub_dir = DirMetadata::new(rand::random(), "Fake", Vec::new(), None);
            dir.sub_dirs_mut().push(sub_dir);

            dir_helper::create(client.clone(), &dir, None)
                .then(move |res| {
                    let dir_id = unwrap!(res);
                    dir_helper::get(c2, &(dir_id, None)).map(move |new_dir| (dir_id, new_dir))
                })
                .then(move |res| {
                    let (dir_id, new_dir) = unwrap!(res);
                    assert_eq!(new_dir, dir);

                    // Create a Child directory and update the parent_dir
                    let child_dir = Dir::new();

                    dir_helper::create(c3, &child_dir, None)
                        .map(move |child_id| (dir_id, child_id, child_dir))
                })
                .then(move |res| {
                    let (dir_id, child_id, mut new_dir) = unwrap!(res);
                    dir_helper::add_sub_dir(c4,
                                            "Child".to_string(),
                                            &(child_id, None),
                                            "test".to_owned().into_bytes(),
                                            &mut new_dir,
                                            &(dir_id, None))
                        .map(move |dir_meta| (dir_meta, new_dir))
                })
                .then(move |res| {
                    let (dir_meta, new_dir) = unwrap!(res);
                    assert_eq!(dir_meta.name(), "Child");
                    assert_eq!(dir_meta.user_metadata(), b"test");
                    assert!(new_dir.find_sub_dir("Child").is_some());

                    dir_helper::create_sub_dir(c5,
                                               "Grand Child".to_string(),
                                               None,
                                               Vec::new(),
                                               &new_dir,
                                               &dir_meta.id())
                        .map(move |(parent_dir, _, grand_child_meta)| {
                            (dir_meta, parent_dir, grand_child_meta)
                        })
                })
                .then(move |res| {
                    let (parent_dir_meta, parent_dir, grand_child_meta) = unwrap!(res);
                    assert_eq!(grand_child_meta.name(), "Grand Child");

                    // We expect result to be an error if we try to create a dir with the same name
                    dir_helper::create_sub_dir(c6,
                                               "Grand Child".to_string(),
                                               None,
                                               Vec::new(),
                                               &parent_dir,
                                               &parent_dir_meta.id())
                })
                .then(|res| {
                    assert!(res.is_err());
                    finish()
                })
        });
    }

    #[test]
    fn create_public_dir() {
        let mut public_dir = Dir::new();
        let sub_dir = DirMetadata::new(rand::random(), "fake_sub_dir", Vec::new(), None);
        public_dir.sub_dirs_mut().push(sub_dir);

        let (tx, rx) = mpsc::channel::<DataIdentifier>();

        let pd = public_dir.clone();
        random_client(move |client| {
            dir_helper::create(client.clone(), &pd, None)
                .map(move |dir_id| unwrap!(tx.send(dir_id)))
        });

        let public_dir_id = rx.recv().unwrap();

        random_client(move |client| {
            dir_helper::get(client.clone(), &(public_dir_id, None)).then(move |res| {
                let retrieved_pub_dir = unwrap!(res);
                assert_eq!(retrieved_pub_dir, public_dir);
                finish()
            })
        });
    }

    #[test]
    fn user_root_configuration() {
        random_client(move |client| {
            let c2 = client.clone();
            let c3 = client.clone();

            dir_helper::user_root_dir(client.clone())
                .then(move |result| {
                    let (mut root_dir, dir_id) = unwrap!(result);
                    dir_helper::create_sub_dir(c2.clone(),
                                               "DirName".to_string(),
                                               None,
                                               Vec::new(),
                                               &mut root_dir,
                                               &dir_id)
                })
                .then(move |res| {
                    let (updated_parent, _, metadata) = unwrap!(res);
                    dir_helper::user_root_dir(c3)
                        .map(move |(dir, _dir_id)| (dir, updated_parent, metadata))
                })
                .then(move |res| {
                    let (root_dir, updated_parent, metadata) = unwrap!(res);
                    assert_eq!(updated_parent, root_dir);
                    assert!(root_dir.find_sub_dir(metadata.name()).is_some());
                    finish()
                })

        });
    }

    #[test]
    fn configuration_directory() {
        random_client(move |client| {
            let c2 = client.clone();

            dir_helper::configuration_dir(client.clone(), "DNS".to_string()).then(move |res| {
                let (_, metadata) = unwrap!(res);
                assert_eq!(metadata.name().clone(), "DNS".to_string());

                let id = metadata.id();

                dir_helper::configuration_dir(c2, "DNS".to_string()).map(move |(_, metadata)| {
                    assert_eq!(metadata.id(), id);
                })
            })
        });
    }

    #[test]
    fn delete_directory() {
        random_client(move |client| {
            // Create a Directory
            let mut parent = Dir::new();
            parent.sub_dirs_mut()
                .push(DirMetadata::new(rand::random(), "fake_sub_dir", Vec::new(), None));

            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();
            let c5 = client.clone();
            let c6 = client.clone();

            dir_helper::create(client.clone(), &parent, None)
                .then(move |res| {
                    let parent_id = unwrap!(res);
                    dir_helper::get(c2, &(parent_id, None))
                        .map(move |get_result| (get_result, parent_id))
                })
                .then(move |res| {
                    let (get_result, parent_id) = unwrap!(res);
                    assert_eq!(parent, get_result);

                    // Create a Child directory and update the parent_dir
                    dir_helper::create_sub_dir(c3,
                                               "Child".to_string(),
                                               None,
                                               Vec::new(),
                                               &parent,
                                               &(parent_id, None))
                })
                .then(move |res| {
                    let (parent_dir, _, metadata) = unwrap!(res);
                    // Assert whether parent is updated
                    assert!(parent_dir.find_sub_dir(metadata.name()).is_some());

                    let dir_id = metadata.id();

                    dir_helper::create_sub_dir(c4,
                                               "Grand Child".to_string(),
                                               None,
                                               Vec::new(),
                                               &parent_dir,
                                               &dir_id)
                        .map(move |(parent_dir, _created_dir, metadata)| {
                            (parent_dir, dir_id, metadata)
                        })
                })
                .then(move |result| {
                    let (mut parent_dir, parent_id, metadata) = unwrap!(result);
                    dir_helper::delete(c5, &mut parent_dir, &parent_id, metadata.name())
                        .map(move |_| parent_id)
                })
                .then(move |parent_id| dir_helper::get(c6, &unwrap!(parent_id)))
                .then(move |res| {
                    let parent_dir = unwrap!(res);
                    assert!(parent_dir.find_sub_dir("Grand Child").is_none());
                    finish()
                })
        });
    }
}
