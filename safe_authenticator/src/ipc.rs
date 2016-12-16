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

use ffi_utils::{FfiString, OpaqueCtx, base64_encode, catch_unwind_cb};
use futures::{Future, future};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Action, ClientError, EntryActions, PermissionSet, User};
use rust_sodium::crypto::{secretbox, sign};
use rust_sodium::crypto::hash::sha256;
use safe_core::{Client, CoreError, FutureExt, MDataInfo, nfs};
use safe_core::ipc::{self, Config, IpcError, IpcMsg, decode_msg};
use safe_core::ipc::req::{AppExchangeInfo, AuthReq, ContainersReq, IpcReq};
use safe_core::ipc::req::ffi::AuthReq as FfiAuthReq;
use safe_core::ipc::req::ffi::ContainersReq as FfiContainersReq;
use safe_core::ipc::req::ffi::Permission;
use safe_core::ipc::resp::{AccessContInfo, AppKeys, AuthGranted, IpcResp};
use safe_core::utils::{symmetric_decrypt, symmetric_encrypt};
use std::collections::{BTreeSet, HashMap};
use std::os::raw::c_void;
use super::{AccessContainerEntry, AuthError, AuthFuture, Authenticator};


const CONFIG_FILE: &'static [u8] = b"authenticator-config";

/// App data stored in the authenticator configuration
#[derive(Clone, RustcEncodable, RustcDecodable)]
pub struct AppInfo {
    /// Application info (id, name, vendor, etc.)
    pub info: AppExchangeInfo,
    /// Application keys
    pub keys: AppKeys,
}

/// Returns true if app is already registered (meaning it has an entry
/// in the config file AND the access container).
fn is_app_registered(client: Client,
                     config: HashMap<sha256::Digest, AppInfo>,
                     app_id: String)
                     -> Box<AuthFuture<bool>> {
    let c2 = client.clone();
    let app_id_hash = sha256::hash(app_id.clone().as_bytes());

    match config.get(&app_id_hash) {
        Some(app) => {
            let app_keys = app.keys.clone();
            access_container(client)
                .and_then(move |dir| access_container_entry(c2, &dir, &app_id, app_keys))
                .then(move |res| Ok(res.is_ok()))
                .into_box()
        }
        None => ok!(false),
    }
}

/// Decodes a given encoded IPC message and calls a corresponding callback
#[no_mangle]
// TODO(nbaksalyar) rename to decode_ipc_msg later
pub unsafe extern "C" fn auth_decode_ipc_msg(auth: *mut Authenticator,
                                             msg: FfiString,
                                             user_data: *mut c_void,
                                             o_auth: extern "C" fn(*mut c_void, u32, FfiAuthReq),
                                             o_containers: extern "C" fn(*mut c_void,
                                                                         u32,
                                                                         FfiContainersReq),
                                             o_err: extern "C" fn(*mut c_void, i32, FfiString)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_err, || -> Result<_, AuthError> {
        let msg = decode_msg(msg.as_str()?)?;
        match msg {
            IpcMsg::Req { req: IpcReq::Auth(auth_req), req_id } => {
                let app_id = auth_req.app.id.clone();
                let app_id2 = app_id.clone();

                (*auth).send(move |client| {
                        let c2 = client.clone();

                        get_config(client.clone())
                            .and_then(move |(_config_version, config)| {
                                is_app_registered(c2, config, app_id)
                            })
                            .and_then(move |is_registered| {
                                if is_registered {
                                    // App is already registered, calling err callback
                                    let resp = encode_response(&IpcMsg::Resp {
                                        req_id: req_id,
                                        resp: IpcResp::Auth(Err(IpcError::AlreadyAuthorised))
                                    }, app_id2)?;

                                    let err = AuthError::from(IpcError::AlreadyAuthorised);

                                    o_err(user_data.0, ffi_error_code!(err), resp);
                                } else {
                                    // App is not registered yet
                                    o_auth(user_data.0, req_id, auth_req.into_repr_c());
                                }
                                Ok(())
                            })
                            .map_err(move |e| {
                                o_err(user_data.0, ffi_error_code!(e), FfiString::default())
                            })
                            .into_box()
                            .into()
                    })?;
            }
            IpcMsg::Req { req: IpcReq::Containers(cont_req), req_id } => {
                o_containers(user_data.0, req_id, cont_req.into_repr_c());
            }
            _ => {
                return Err(IpcError::InvalidMsg.into());
            }
        }
        Ok(())
    })
}

/// Retrieves the authenticator configuration file
pub fn get_config(client: Client) -> Box<AuthFuture<(u64, HashMap<sha256::Digest, AppInfo>)>> {
    let parent = fry!(client.config_root_dir());
    let key = fry!(parent.enc_entry_key(CONFIG_FILE));

    client.get_mdata_value(parent.name, parent.type_tag, key)
        .and_then(move |val| {
            let plaintext = parent.decrypt(&val.content)?;
            let file = deserialise::<HashMap<sha256::Digest, AppInfo>>(&plaintext)?;
            Ok((val.entry_version, file))
        })
        .map_err(From::from)
        .into_box()
}

/// Retrieves an app info by the given key from the config file
pub fn app_info(client: Client, app_id: &str) -> Box<AuthFuture<Option<AppInfo>>> {
    let app_id_hash = sha256::hash(app_id.as_bytes());
    get_config(client)
        .and_then(move |(_, config)| Ok(config.get(&app_id_hash).cloned()))
        .into_box()
}

/// Updates the authenticator configuration file and returns the updated `File` struct.
fn update_config(client: Client,
                 version: Option<u64>,
                 auth_cfg: HashMap<sha256::Digest, AppInfo>)
                 -> Box<AuthFuture<()>> {
    let parent = fry!(client.config_root_dir());

    let key = fry!(parent.enc_entry_key(CONFIG_FILE));
    let plaintext = fry!(serialise(&auth_cfg));
    let ciphertext = fry!(parent.enc_entry_value(&plaintext));

    let actions = if let Some(version) = version {
        EntryActions::new().update(key, ciphertext, version)
    } else {
        EntryActions::new().ins(key, ciphertext, 0)
    };

    client.mutate_mdata_entries(parent.name, parent.type_tag, actions.into())
        .map_err(From::from)
        .into_box()
}

/// Encrypts and serialises an access container key using given app ID and app keys
pub fn access_container_key(dir: &MDataInfo,
                            app_id: &str,
                            app_keys: &AppKeys)
                            -> Result<Vec<u8>, AuthError> {
    let dir_nonce = if let Some((_, Some(dir_nonce))) = dir.enc_info {
        dir_nonce
    } else {
        // No valid nonce for the MDataInfo could be found
        return Err(AuthError::Unexpected("No valid nonce for access container".to_owned()));
    };

    let key = app_id.as_bytes();

    let mut key_pt = key.to_vec();
    key_pt.extend_from_slice(&dir_nonce[..]);

    let key_nonce =
        unwrap!(secretbox::Nonce::from_slice(&sha256::hash(&key_pt)[..secretbox::NONCEBYTES]));
    Ok(secretbox::seal(key, &key_nonce, &app_keys.enc_key))
}

/// Retrieves the authenticator configuration file
pub fn access_container(client: Client) -> Box<AuthFuture<MDataInfo>> {
    let parent = fry!(client.config_root_dir());
    let key = fry!(parent.enc_entry_key(b"access-container"));

    client.get_mdata_value(parent.name, parent.type_tag, key)
        .map_err(From::from)
        .and_then(move |val| {
            let content = parent.decrypt(&val.content)?;
            deserialise::<MDataInfo>(&content).map_err(From::from)
        })
        .into_box()
}

/// Gets an access container entry
pub fn access_container_entry(client: Client,
                              dir: &MDataInfo,
                              app_id: &str,
                              app_keys: AppKeys)
                              -> Box<AuthFuture<(u64, AccessContainerEntry)>> {
    let key = fry!(access_container_key(dir, &app_id, &app_keys));

    client.get_mdata_value(dir.name, dir.type_tag, key)
        .and_then(move |value| {
            let plaintext = symmetric_decrypt(&value.content, &app_keys.enc_key)?;
            Ok((value.entry_version, deserialise(&plaintext)?))
        })
        .map_err(From::from)
        .into_box()
}

/// Adds a new entry to the authenticator access container
fn put_access_container_entry(client: Client,
                              dir: &MDataInfo,
                              app_id: &str,
                              app_keys: &AppKeys,
                              permissions: AccessContainerEntry,
                              version: Option<u64>)
                              -> Box<AuthFuture<()>> {
    let key = fry!(access_container_key(dir, app_id, app_keys));
    let plaintext = fry!(serialise(&permissions));
    let ciphertext = fry!(symmetric_encrypt(&plaintext, &app_keys.enc_key, None));

    let actions = if let Some(version) = version {
        EntryActions::new().update(key, ciphertext, version)
    } else {
        EntryActions::new().ins(key, ciphertext, 0)
    };

    client.mutate_mdata_entries(dir.name, dir.type_tag, actions.into())
        .map_err(From::from)
        .into_box()
}

/// Adds the given app info to the configuration file
fn insert_app_to_config(client: Client, app: AppInfo) -> Box<AuthFuture<()>> {
    let c2 = client.clone();
    let app_id_hash = sha256::hash(app.info.id.as_bytes());

    get_config(client.clone())
        .and_then(move |(version, mut auth_cfg)| {
            // Add app info to the authenticator config
            let _ = auth_cfg.insert(app_id_hash, app);
            update_config(c2, Some(version + 1), auth_cfg)
        })
        .into_box()
}

/// Updates containers permissions
fn update_container_perms(client: Client,
                          permissions: HashMap<String, BTreeSet<Permission>>,
                          sign_pk: sign::PublicKey)
                          -> Box<AuthFuture<AccessContainerEntry>> {
    let root = fry!(client.user_root_dir());
    let mut reqs = Vec::new();

    for (container_key, access) in permissions {
        let key = fry!(root.enc_entry_key(container_key.as_bytes()));
        let perm_set = convert_permission_set(&access);

        let c2 = client.clone();
        let c3 = client.clone();
        let dir2 = root.clone();

        reqs.push(client.clone()
            .get_mdata_value(root.name, root.type_tag, key)
            .and_then(move |val| {
                let plaintext = fry!(dir2.decrypt(&val.content));
                let dir = fry!(deserialise::<MDataInfo>(&plaintext));

                c2.get_mdata_version(dir.name, dir.type_tag)
                    .map(move |version| (dir, version))
                    .into_box()
            })
            .and_then(move |(dir, version)| {
                c3.set_mdata_user_permissions(dir.name,
                                                dir.type_tag,
                                                User::Key(sign_pk),
                                                perm_set,
                                                version + 1)
                    .map(move |_| (container_key, dir, access))
            })
            .map_err(AuthError::from));
    }

    future::join_all(reqs)
        .map(|perms| {
            perms.into_iter().fold(HashMap::new(), |mut map, (container_key, dir, access)| {
                let _ = map.insert(container_key, (dir, access));
                map
            })
        })
        .map_err(AuthError::from)
        .into_box()
}

fn encode_auth_resp_impl(client: Client,
                         app: AppInfo,
                         app_container: bool,
                         permissions: HashMap<String, BTreeSet<Permission>>)
                         -> Box<AuthFuture<AuthGranted>> {
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();
    let c5 = client.clone();
    let c6 = client.clone();

    let sign_pk = app.keys.sign_pk;
    let app_keys = app.keys.clone();
    let app_info = app.info.clone();
    let app_id = app_info.id.clone();

    client.ins_auth_key(app.keys.sign_pk, 0)
        .map_err(AuthError::from)
        .and_then(move |_| insert_app_to_config(c2, app))
        .and_then(move |_| update_container_perms(c3, permissions, sign_pk))
        .and_then(move |perms| {
            if app_container {
                check_app_container(c4, app_id, sign_pk)
                    .map(move |mdata_info| (mdata_info, perms))
                    .into_box()
            } else {
                ok!((None, perms))
            }
        })
        .and_then(move |(app_container, perms)| {
            // Update access_container
            access_container(c5).map(move |dir| (dir, app_container, perms))
        })
        .and_then(move |(dir, app_container, mut perms)| {
            if let Some(mdata_info) = app_container {
                // Store info about the app's dedicated container in the access container
                let mut access = BTreeSet::new();
                let _ = access.insert(Permission::Read);
                let _ = access.insert(Permission::Insert);
                let _ = access.insert(Permission::Update);
                let _ = access.insert(Permission::Delete);
                let _ = access.insert(Permission::ManagePermissions);

                let _ = perms.insert(app_info.id.clone(), (mdata_info, access));
            };
            put_access_container_entry(c6, &dir, &app_info.id, &app_keys, perms, None)
                .map(move |_| (dir, app_keys))
        })
        .and_then(move |(dir, app_keys)| {
            Ok(AuthGranted {
                app_keys: app_keys,
                bootstrap_config: Config {},
                access_container: AccessContInfo::from_mdata_info(dir)?,
            })
        })
        .into_box()
}

/// Creates a new app dedicated container
fn create_app_container(client: Client,
                        app_id: String,
                        app_sign_pk: sign::PublicKey)
                        -> Box<AuthFuture<MDataInfo>> {
    let root = fry!(client.user_root_dir());
    let app_cont_name = format!("apps/{}", app_id);

    let c2 = client.clone();

    nfs::create_dir(&client, false)
        .map_err(From::from)
        .and_then(move |dir| {
            let serialised = fry!(serialise(&dir));
            let key = fry!(root.enc_entry_key(app_cont_name.as_bytes()));
            let ciphertext = fry!(root.enc_entry_value(&serialised));

            let actions = EntryActions::new().ins(key, ciphertext, 0);
            client.mutate_mdata_entries(root.name, root.type_tag, actions.into())
                .map_err(From::from)
                .map(move |_| dir)
                .into_box()
        })
        .and_then(move |dir| {
            let mut ps = PermissionSet::new();
            let _ = ps.allow(Action::Insert)
                .allow(Action::Update)
                .allow(Action::Delete)
                .allow(Action::ManagePermissions);

            c2.set_mdata_user_permissions(dir.name, dir.type_tag, User::Key(app_sign_pk), ps, 1)
                .map_err(From::from)
                .map(move |_| dir)
        })
        .into_box()
}

/// Checks if an app's dedicated container is available and stored in the user's root dir.
/// If `Some(MDataInfo)` is returned then the container has been created.
fn check_app_container(client: Client,
                       app_id: String,
                       app_sign_pk: sign::PublicKey)
                       -> Box<AuthFuture<Option<MDataInfo>>> {
    let root = fry!(client.user_root_dir());
    let app_cont_name = format!("apps/{}", app_id);
    let key = fry!(root.enc_entry_key(app_cont_name.as_bytes()));

    client.get_mdata_value(root.name, root.type_tag, key)
        .then(move |res| {
            match res {
                Err(CoreError::RoutingClientError(ClientError::NoSuchEntry)) => {
                    // Proceed to create a container
                    create_app_container(client, app_id, app_sign_pk)
                        .map(Some)
                        .into_box()
                }
                Err(e) => err!(e),
                Ok(_) => ok!(None),
            }
        })
        .into_box()
}

/// Provides and encodes an Authenticator response
#[no_mangle]
pub unsafe extern "C" fn encode_auth_resp(auth: *mut Authenticator,
                                          req: FfiAuthReq,
                                          req_id: u32,
                                          is_granted: bool,
                                          user_data: *mut c_void,
                                          o_cb: extern "C" fn(*mut c_void, i32, FfiString)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), AuthError> {
        let auth_req = AuthReq::from_repr_c(req)?;

        if !is_granted {
            let resp = encode_response(&IpcMsg::Resp {
                                           req_id: req_id,
                                           resp: IpcResp::Auth(Err(IpcError::AuthDenied)),
                                       },
                                       auth_req.app.id)?;
            o_cb(user_data.0,
                 ffi_error_code!(AuthError::from(IpcError::AuthDenied)),
                 resp);
        } else {
            let permissions = auth_req.containers.clone();

            (*auth).send(move |client| {
                    let owner_key =
                        try_cb!(client.owner_key().map_err(AuthError::from), user_data, o_cb);
                    let keys = AppKeys::random(owner_key);

                    let app = AppInfo {
                        info: auth_req.app,
                        keys: keys,
                    };
                    let app_id = app.info.id.clone();
                    let app_id2 = app_id.clone();

                    encode_auth_resp_impl(client.clone(), app, auth_req.app_container, permissions)
                        .and_then(move |auth_granted| {
                            Ok(o_cb(user_data.0,
                                    0,
                                    encode_response(&IpcMsg::Resp {
                                                        req_id: req_id,
                                                        resp: IpcResp::Auth(Ok(auth_granted)),
                                                    },
                                                    app_id)?))
                        })
                        .or_else(move |e| -> Result<(), AuthError> {
                            Ok(o_cb(user_data.0,
                                    ffi_error_code!(e),
                                    encode_response(&IpcMsg::Resp {
                                                        req_id: req_id,
                                                        resp: IpcResp::Auth(Err(e.into())),
                                                    },
                                                    app_id2)?))
                        })
                        .map_err(move |e| debug!("Unexpected error: {:?}", e))
                        .into_box()
                        .into()
                })?;
        }

        Ok(())
    })
}

/// Update containers permissions for an App
#[no_mangle]
pub unsafe extern "C" fn encode_containers_resp(auth: *mut Authenticator,
                                                req: FfiContainersReq,
                                                req_id: u32,
                                                is_granted: bool,
                                                user_data: *mut c_void,
                                                o_cb: extern "C" fn(*mut c_void, i32, FfiString)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), AuthError> {
        let cont_req = ContainersReq::from_repr_c(req)?;

        if !is_granted {
            let resp = IpcMsg::Resp {
                req_id: req_id,
                resp: IpcResp::Containers(Err(IpcError::AuthDenied)),
            };
            o_cb(user_data.0,
                 ffi_error_code!(AuthError::from(IpcError::AuthDenied)),
                 encode_response(&resp, cont_req.app.id)?);
        } else {
            let permissions = cont_req.containers.clone();
            let app_id = cont_req.app.id.clone();
            let app_id2 = app_id.clone();

            (*auth).send(move |client| {
                    let c2 = client.clone();
                    let c3 = client.clone();
                    let c4 = client.clone();
                    let c5 = client.clone();

                    app_info(client.clone(), &app_id)
                        .and_then(move |app| {
                            match app {
                                Some(app) => {
                                    let sign_pk = app.keys.sign_pk;
                                    update_container_perms(c2, permissions, sign_pk)
                                        .map(move |perms| (app, perms))
                                        .into_box()
                                }
                                None => err!(IpcError::UnknownApp),
                            }
                        })
                        .and_then(move |(app, perms)| {
                            access_container(c3).map(move |dir| (dir, app, perms))
                        })
                        .and_then(move |(dir, app, perms)| {
                            let app_keys = app.keys;

                            access_container_entry(c4, &dir, &app_id, app_keys.clone())
                                .then(move |res| {
                                    let version = match res {
                                        Ok((version, _)) => Some(version),
                                        // Adding a new access container entry
                                        Err(AuthError::CoreError(
                                        CoreError::RoutingClientError(
                                            ClientError::NoSuchEntry))) => None,
                                        Err(e) => return err!(e),
                                    };
                                    ok!((version, app_id, app_keys, dir, perms))
                                })
                        })
                        .and_then(move |(version, app_id, app_keys, dir, perms)| {
                            put_access_container_entry(c5, &dir, &app_id, &app_keys, perms, version)
                        })
                        .and_then(move |_| {
                            let resp = IpcMsg::Resp {
                                req_id: req_id,
                                resp: IpcResp::Containers(Ok(())),
                            };
                            o_cb(user_data.0, 0, encode_response(&resp, cont_req.app.id)?);
                            Ok(())
                        })
                        .or_else(move |e| -> Result<(), AuthError> {
                            Ok(o_cb(user_data.0,
                                    ffi_error_code!(e),
                                    encode_response(&IpcMsg::Resp {
                                                        req_id: req_id,
                                                        resp: IpcResp::Containers(Err(e.into())),
                                                    },
                                                    app_id2)?))
                        })
                        .map_err(move |e| debug!("Unexpected error: {:?}", e))
                        .into_box()
                        .into()
                })?;
        }

        Ok(())
    });
}

fn encode_response(msg: &IpcMsg, app_id: String) -> Result<FfiString, IpcError> {
    let app_id = base64_encode(app_id.as_bytes());
    let resp = ipc::encode_msg(msg, "safe-auth")?;
    Ok(FfiString::from_string(format!("safe-{}:{}", app_id, resp)))
}

fn convert_permission_set<'a, Iter>(permissions: Iter) -> PermissionSet
    where Iter: IntoIterator<Item = &'a Permission>
{
    let mut ps = PermissionSet::new();

    for access in permissions {
        match *access {
            Permission::Read => {}
            Permission::Insert => {
                let _ = ps.allow(Action::Insert);
            }
            Permission::Update => {
                let _ = ps.allow(Action::Update);
            }
            Permission::Delete => {
                let _ = ps.allow(Action::Delete);
            }
            Permission::ManagePermissions => {
                let _ = ps.allow(Action::ManagePermissions);
            }
        }
    }

    ps
}

#[cfg(test)]
mod tests {}
