// Copyright 2017 MaidSafe.net limited.
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

use super::utils::{Payload, decode_ipc_msg};
use errors::{AuthError, ERR_INVALID_OWNER, ERR_SHARE_MDATA_DENIED};
use ffi::apps::*;
use ffi::ipc::encode_share_mdata_resp;
use ffi_utils::FfiResult;
use ffi_utils::test_utils::{call_vec, send_via_user_data, sender_as_user_data};
use futures::Future;
use maidsafe_utilities::serialisation::serialise;
use rand;
use routing::{Action, MutableData, PermissionSet, User, Value};
use rust_sodium::crypto::sign;
use safe_core::ipc::{self, AuthReq, IpcMsg, IpcReq, ShareMData, ShareMDataReq};
use safe_core::ipc::req::AppExchangeInfo;
use safe_core::ipc::resp::{AppAccess, METADATA_KEY, UserMetadata};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::sync::mpsc;
use std::time::Duration;
use test_utils::{create_account_and_login, rand_app, register_app, run};

#[test]
fn share_zero_mdatas() {
    let authenticator = create_account_and_login();

    let msg = IpcMsg::Req {
        req_id: ipc::gen_req_id(),
        req: IpcReq::ShareMData(ShareMDataReq {
            app: rand_app(),
            mdata: vec![],
        }),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    let decoded = unwrap!(decode_ipc_msg(&authenticator, &encoded_msg));
    match decoded {
        (IpcMsg::Req { req: IpcReq::ShareMData(ShareMDataReq { mdata, .. }), .. },
         Some(Payload::Metadata(metadatas))) => {
            assert_eq!(mdata.len(), 0);
            assert_eq!(metadatas.len(), 0);
        }
        _ => panic!("Unexpected: {:?}", decoded),
    };
}

#[test]
fn share_some_mdatas() {
    let authenticator = create_account_and_login();

    let user = run(&authenticator, move |client| {
        client.public_signing_key().map_err(AuthError::CoreError)
    });

    const NUM_MDATAS: usize = 3;

    let mut mdatas = Vec::new();
    let mut metadatas = Vec::new();

    for _ in 0..NUM_MDATAS {
        let name = rand::random();
        let tag = 0;
        let mdata = {
            let owners = btree_set![user];
            unwrap!(MutableData::new(
                name,
                tag,
                btree_map![],
                btree_map![],
                owners,
            ))
        };

        run(&authenticator, move |client| {
            client.put_mdata(mdata).map_err(AuthError::CoreError)
        });

        mdatas.push(ShareMData {
            type_tag: tag,
            name: name,
            perms: PermissionSet::new().allow(Action::Insert),
        });
        metadatas.push((None, name, tag));
    }

    let msg = IpcMsg::Req {
        req_id: ipc::gen_req_id(),
        req: IpcReq::ShareMData(ShareMDataReq {
            app: rand_app(),
            mdata: mdatas.clone(),
        }),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    let decoded = unwrap!(decode_ipc_msg(&authenticator, &encoded_msg));
    match decoded {
        (IpcMsg::Req { req: IpcReq::ShareMData(ShareMDataReq { mdata, .. }), .. },
         Some(Payload::Metadata(received_metadatas))) => {
            assert_eq!(mdata, mdatas);
            assert_eq!(received_metadatas, metadatas);
        }
        _ => panic!("Unexpected: {:?}", decoded),
    };
}

#[test]
fn share_some_mdatas_with_valid_metadata() {
    let authenticator = create_account_and_login();

    let app_id = rand_app();
    let auth_req = AuthReq {
        app: app_id.clone(),
        app_container: false,
        containers: Default::default(),
    };

    let app_auth = unwrap!(register_app(&authenticator, &auth_req));
    let app_key = app_auth.app_keys.sign_pk;

    let user = run(&authenticator, move |client| {
        client.public_signing_key().map_err(AuthError::CoreError)
    });

    const NUM_MDATAS: usize = 3;

    let perms = PermissionSet::new().allow(Action::Insert);
    let mut mdatas = Vec::new();
    let mut metadatas = Vec::new();
    for i in 0..NUM_MDATAS {
        let metadata = UserMetadata {
            name: Some(format!("name {}", i)),
            description: Some(format!("description {}", i)),
        };

        let name = rand::random();
        let tag = 10_000;
        let mdata = {
            let value = Value {
                content: unwrap!(serialise(&metadata)),
                entry_version: 0,
            };
            let owners = btree_set![user];
            let entries = btree_map![METADATA_KEY.to_vec() => value];
            unwrap!(MutableData::new(
                name,
                tag,
                BTreeMap::new(),
                entries,
                owners,
            ))
        };

        run(&authenticator, move |client| {
            client.put_mdata(mdata).map_err(AuthError::CoreError)
        });

        mdatas.push(ShareMData {
            type_tag: tag,
            name: name,
            perms: perms,
        });
        metadatas.push((Some(metadata), name, tag));
    }

    let req_id = ipc::gen_req_id();
    let req = ShareMDataReq {
        app: app_id,
        mdata: mdatas.clone(),
    };
    let msg = IpcMsg::Req {
        req_id: req_id,
        req: IpcReq::ShareMData(req.clone()),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    let decoded = unwrap!(decode_ipc_msg(&authenticator, &encoded_msg));
    match decoded {
        (IpcMsg::Req { req: IpcReq::ShareMData(ShareMDataReq { mdata, .. }), .. },
         Some(Payload::Metadata(received_metadatas))) => {
            assert_eq!(mdata, mdatas);
            assert_eq!(received_metadatas, metadatas);
        }
        _ => panic!("Unexpected: {:?}", decoded),
    };

    let (tx, rx) = mpsc::channel::<Result<(), (i32, String)>>();
    let req_c = unwrap!(req.into_repr_c());
    unsafe {
        encode_share_mdata_resp(
            &authenticator,
            &req_c,
            req_id,
            true,
            sender_as_user_data::<Result<(), (i32, String)>>(&tx),
            encode_share_mdata_cb,
        );
    }

    unwrap!(unwrap!(rx.recv_timeout(Duration::from_secs(15))));

    for share_mdata in &mdatas {
        let name = share_mdata.name;
        let type_tag = share_mdata.type_tag;
        let mdata = run(&authenticator, move |client| {
            client.get_mdata(name, type_tag).map_err(
                AuthError::CoreError,
            )
        });
        let permissions = unwrap!(mdata.user_permissions(&User::Key(app_key)));
        assert_eq!(permissions, &perms);
    }
}

#[test]
fn share_some_mdatas_with_ownership_error() {
    let authenticator = create_account_and_login();

    let user = run(&authenticator, move |client| {
        client.public_signing_key().map_err(AuthError::CoreError)
    });

    let (someone_else, _) = sign::gen_keypair();

    let ownerss = vec![
        btree_set![user /* , someone_else */], // currently can't handle having multiple owners
        btree_set![someone_else],
        btree_set![user],
        btree_set![],
    ];

    let mut mdatas = Vec::new();
    for owners in ownerss {
        let name = rand::random();
        let mdata = {
            unwrap!(MutableData::new(
                name,
                0,
                btree_map![],
                btree_map![],
                owners,
            ))
        };

        run(&authenticator, move |client| {
            client.put_mdata(mdata).map_err(AuthError::CoreError)
        });

        mdatas.push(ShareMData {
            type_tag: 0,
            name: name,
            perms: PermissionSet::new().allow(Action::Insert),
        });
    }

    let req_id = ipc::gen_req_id();
    let req = ShareMDataReq {
        app: rand_app(),
        mdata: mdatas.clone(),
    };
    let msg = IpcMsg::Req {
        req_id: req_id,
        req: IpcReq::ShareMData(req.clone()),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    match decode_ipc_msg(&authenticator, &encoded_msg) {
        Ok(..) => (),
        Err(err) => {
            assert_eq!(err, (ERR_INVALID_OWNER, None));
        }
    };

    let (tx, rx) = mpsc::channel::<Result<(), (i32, String)>>();
    let req_c = unwrap!(req.into_repr_c());
    unsafe {
        encode_share_mdata_resp(
            &authenticator,
            &req_c,
            req_id,
            false,
            sender_as_user_data::<Result<(), (i32, String)>>(&tx),
            encode_share_mdata_cb,
        );
    }

    match unwrap!(rx.recv_timeout(Duration::from_secs(15))) {
        Ok(()) => panic!("unexpected success"),
        Err((ERR_SHARE_MDATA_DENIED, _)) => (),
        Err((code, description)) => panic!("Unexpected error ({}): {}", code, description),
    };
}

// Test cases for:
// 1. Shared access is requested for an MData object that has metadata.
// a. Test that `name` and `description` were returned correctly. (This should mostly be covered by
// various tests in `safe_authenticator::tests` such as `share_some_mdatas()`.) Check that the
// returned `xor_name` and `type_tag` can identify the right MData.
// b. Add some tests similar to 2b and 2c (below), but where the MData does have metadata. The
// behavior should be the same.
// 2. Shared access is requested for an MData object that doesn't have metadata.
// a. Test that null was returned for the MD name and description, but that the returned `xor_name`
// and `type_tag` can correctly identify the right MData.
// b. Test that we can get the apps accessing the MData with `auth_apps_accessing_mutable_data`.
// Namely, each `AppAccess` object should contain all the correct information.
// c. If an app is listed in the MD permissions list, but is not listed in the registered apps list
// in Authenticator, then test that the `app_id` and `name` fields are null, but the public sign key
// and the list of permissions are correct.
#[test]
fn auth_apps_accessing_mdatas() {
    let authenticator = create_account_and_login();

    let user = run(&authenticator, move |client| {
        client.public_signing_key().map_err(AuthError::CoreError)
    });

    const NUM_MDATAS: usize = 3;
    const NUM_MDATAS_NO_META: usize = 3;

    // Create a few MData objects with metadata
    let perms = PermissionSet::new().allow(Action::Insert);
    let mut mdatas = Vec::new();
    let mut metadatas = Vec::new();
    let unregistered = sign::gen_keypair().0;

    for i in 0..(NUM_MDATAS + NUM_MDATAS_NO_META) {
        let metadata = if i < NUM_MDATAS {
            Some(UserMetadata {
                name: Some(format!("name {}", i)),
                description: Some(format!("description {}", i)),
            })
        } else {
            None
        };

        let name = rand::random();
        let tag = 10_000 + i as u64;
        let mdata = {
            let owners = btree_set![user];

            // We need to test both with and without metadata
            let entries = match metadata {
                Some(ref meta) => {
                    let value = Value {
                        content: unwrap!(serialise(&meta)),
                        entry_version: 0,
                    };
                    btree_map![METADATA_KEY.to_vec() => value]
                }
                None => btree_map![],
            };

            // Include one app in the permissions list that is not registered
            unwrap!(MutableData::new(
                name,
                tag,
                btree_map![User::Key(unregistered) => perms],
                entries,
                owners,
            ))
        };

        run(&authenticator, move |client| {
            client.put_mdata(mdata).map_err(AuthError::CoreError)
        });

        mdatas.push(ShareMData {
            type_tag: tag,
            name: name,
            perms: perms,
        });
        metadatas.push((metadata, name, tag));
    }

    const NUM_APPS: usize = 3;

    let mut apps: Vec<(sign::PublicKey, AppExchangeInfo)> = Vec::with_capacity(NUM_APPS);
    for _ in 0..NUM_APPS {
        // Create an app and register it.
        let app_id = rand_app();
        let auth_req = AuthReq {
            app: app_id.clone(),
            app_container: false,
            containers: Default::default(),
        };

        let app_auth = unwrap!(register_app(&authenticator, &auth_req));
        let app_key = app_auth.app_keys.sign_pk;

        // Share the Mdatas with the app.
        let req_id = ipc::gen_req_id();
        let req = ShareMDataReq {
            app: app_id.clone(),
            mdata: mdatas.clone(),
        };
        let msg = IpcMsg::Req {
            req_id: req_id,
            req: IpcReq::ShareMData(req.clone()),
        };
        let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

        let decoded = unwrap!(decode_ipc_msg(&authenticator, &encoded_msg));

        match decoded {
            (IpcMsg::Req { req: IpcReq::ShareMData(ShareMDataReq { mdata, .. }), .. },
             Some(Payload::Metadata(received_metadatas))) => {
                assert_eq!(mdata, mdatas);
                // Ensure the received metadatas, xor names and type tags are equal.
                // For mdata without metadata, received metadata should be `None`.
                assert_eq!(received_metadatas, metadatas);
            }
            _ => panic!("Unexpected: {:?}", decoded),
        };

        let (tx, rx) = mpsc::channel::<Result<(), (i32, String)>>();
        let req_c = unwrap!(req.into_repr_c());
        unsafe {
            encode_share_mdata_resp(
                &authenticator,
                &req_c,
                req_id,
                true,
                sender_as_user_data::<Result<(), (i32, String)>>(&tx),
                encode_share_mdata_cb,
            );
        }

        unwrap!(unwrap!(rx.recv_timeout(Duration::from_secs(15))));

        apps.push((app_key, app_id));
    }

    // Test the correctness of returned `AppAccess` objects
    for (_, name, tag) in metadatas {
        let app_access: Vec<AppAccess> = unsafe {
            unwrap!(call_vec(|ud, cb| {
                auth_apps_accessing_mutable_data(&authenticator, &name.0, tag, ud, cb)
            }))
        };

        // Check each accessing app
        for &(ref app_key, ref app_id) in &apps {
            let access = match app_access.iter().find(
                |&access| access.sign_key == *app_key,
            ) {
                Some(access) => access,
                None => panic!("App not found in AppAccess list."),
            };

            assert_eq!(access.permissions, perms);
            assert_eq!(access.name, Some(app_id.name.clone()));
            assert_eq!(access.app_id, Some(app_id.id.clone()));
        }

        // Check unregistered app
        let access = match app_access.iter().find(
            |&access| access.sign_key == unregistered,
        ) {
            Some(access) => access,
            None => panic!("Unregistered app not found in AppAccess list."),
        };

        assert_eq!(access.permissions, perms);
        assert_eq!(access.name, Some(String::from("")));
        assert_eq!(access.app_id, Some(String::from("")));
    }
}

extern "C" fn encode_share_mdata_cb(
    user_data: *mut c_void,
    result: FfiResult,
    _msg: *const c_char,
) {
    let ret = if result.error_code == 0 {
        Ok(())
    } else {
        let c_str = unsafe { CStr::from_ptr(result.description) };
        let msg = match c_str.to_str() {
            Ok(s) => s.to_owned(),
            Err(e) => {
                format!(
                    "utf8-error in error string: {} {:?}",
                    e,
                    c_str.to_string_lossy()
                )
            }
        };
        Err((result.error_code, msg))
    };
    unsafe {
        send_via_user_data::<Result<(), (i32, String)>>(user_data, ret);
    }
}
