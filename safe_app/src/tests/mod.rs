// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod coins;
mod mutable_data;
mod unpublished_mutable_data;

use crate::ffi::test_utils::test_create_app_with_access;
use crate::test_utils::{create_app_by_req, create_auth_req, create_auth_req_with_access};
use crate::test_utils::{create_random_auth_req, gen_app_exchange_info};
use crate::{run, App, AppError};
use ffi_utils::test_utils::call_1;
use futures::Future;
#[cfg(feature = "mock-network")]
use routing::{ClientError, Request, Response};
use safe_authenticator::test_utils as authenticator;
use safe_authenticator::test_utils::revoke;
use safe_authenticator::{run as auth_run, AuthError, Authenticator};
use safe_core::ipc::req::{AppExchangeInfo, AuthReq};
use safe_core::ipc::Permission;
use safe_core::utils;
use safe_core::utils::test_utils::random_client;
#[cfg(feature = "mock-network")]
use safe_core::MockRouting;
use safe_core::{Client, CoreError};
use safe_nd::{
    ADataAddress, ADataOwner, AppPermissions, AppendOnlyData, Coins, Error as SndError,
    PubImmutableData, PubUnseqAppendOnlyData, UnpubUnseqAppendOnlyData, XorName,
};
use std::collections::HashMap;
use std::rc::Rc;

// Test refreshing access info by fetching it from the network.
#[test]
fn refresh_access_info() {
    // Shared container
    let mut container_permissions = HashMap::new();
    let _ = container_permissions.insert(
        "_videos".to_string(),
        btree_set![Permission::Read, Permission::Insert],
    );

    let app = unwrap!(create_app_by_req(&create_auth_req_with_access(
        container_permissions.clone()
    ),));

    unwrap!(run(&app, move |client, context| {
        let reg = Rc::clone(unwrap!(context.as_registered()));
        assert!(reg.access_info.borrow().is_empty());

        context.refresh_access_info(client).then(move |result| {
            unwrap!(result);
            let access_info = reg.access_info.borrow();
            assert_eq!(
                unwrap!(access_info.get("_videos")).1,
                *unwrap!(container_permissions.get("_videos"))
            );

            Ok(())
        })
    }));
}

// Test fetching containers that an app has access to.
#[test]
#[allow(unsafe_code)]
fn get_access_info() {
    let mut container_permissions = HashMap::new();
    let _ = container_permissions.insert("_videos".to_string(), btree_set![Permission::Read]);
    let _ = container_permissions.insert("_downloads".to_string(), btree_set![Permission::Insert]);

    let auth_req = create_auth_req(None, Some(container_permissions));
    let auth_req_ffi = unwrap!(auth_req.into_repr_c());

    let app: *mut App = unsafe {
        unwrap!(call_1(|ud, cb| test_create_app_with_access(
            &auth_req_ffi,
            ud,
            cb
        ),))
    };

    unwrap!(run(unsafe { &*app }, move |client, context| {
        context.get_access_info(client).then(move |res| {
            let info = unwrap!(res);
            assert!(info.contains_key(&"_videos".to_string()));
            assert!(info.contains_key(&"_downloads".to_string()));
            assert_eq!(info.len(), 3); // third item is the app container

            let (ref _md_info, ref perms) = info["_videos"];
            assert_eq!(perms, &btree_set![Permission::Read]);

            let (ref _md_info, ref perms) = info["_downloads"];
            assert_eq!(perms, &btree_set![Permission::Insert]);

            Ok(())
        })
    }));
}

// Make sure we can login to a registered app with low balance.
#[cfg(feature = "mock-network")]
#[test]
pub fn login_registered_with_low_balance() {
    // Register a hook prohibiting mutations and login
    let routing_hook = move |mut routing: MockRouting| -> MockRouting {
        routing.set_request_hook(move |req| {
            match *req {
                Request::PutIData { msg_id, .. } => Some(Response::PutIData {
                    res: Err(ClientError::LowBalance),
                    msg_id,
                }),
                Request::PutMData { msg_id, .. } => Some(Response::PutMData {
                    res: Err(ClientError::LowBalance),
                    msg_id,
                }),
                Request::MutateMDataEntries { msg_id, .. } => Some(Response::MutateMDataEntries {
                    res: Err(ClientError::LowBalance),
                    msg_id,
                }),
                Request::SetMDataUserPermissions { msg_id, .. } => {
                    Some(Response::SetMDataUserPermissions {
                        res: Err(ClientError::LowBalance),
                        msg_id,
                    })
                }
                Request::DelMDataUserPermissions { msg_id, .. } => {
                    Some(Response::DelMDataUserPermissions {
                        res: Err(ClientError::LowBalance),
                        msg_id,
                    })
                }
                Request::ChangeMDataOwner { msg_id, .. } => Some(Response::ChangeMDataOwner {
                    res: Err(ClientError::LowBalance),
                    msg_id,
                }),
                // Request::InsAuthKey { msg_id, .. } => Some(Response::InsAuthKey {
                //     res: Err(ClientError::LowBalance),
                //     msg_id,
                // }),
                // Request::DelAuthKey { msg_id, .. } => Some(Response::DelAuthKey {
                //     res: Err(ClientError::LowBalance),
                //     msg_id,
                // }),
                // Pass-through
                _ => None,
            }
        });
        routing
    };

    // Login to the client
    let auth = authenticator::create_account_and_login();

    // Register and login to the app
    let app_info = gen_app_exchange_info();
    let app_id = app_info.id.clone();

    let auth_granted = unwrap!(authenticator::register_app(
        &auth,
        &AuthReq {
            app: app_info,
            app_container: false,
            app_permissions: Default::default(),
            containers: HashMap::new(),
        },
    ));

    let _app = unwrap!(App::registered_with_hook(
        app_id,
        auth_granted,
        || (),
        routing_hook,
    ));
}

// Authorise an app with `app_container`.
fn authorise_app(
    auth: &Authenticator,
    app_info: &AppExchangeInfo,
    app_id: &str,
    app_container: bool,
) -> App {
    let auth_granted = unwrap!(authenticator::register_app(
        auth,
        &AuthReq {
            app: app_info.clone(),
            app_container,
            app_permissions: Default::default(),
            containers: HashMap::new(),
        },
    ));

    unwrap!(App::registered(String::from(app_id), auth_granted, || ()))
}

// Get the number of containers for `app`
fn num_containers(app: &App) -> usize {
    unwrap!(run(app, move |client, context| {
        context.get_access_info(client).then(move |res| {
            let info = unwrap!(res);
            Ok(info.len())
        })
    }))
}

// Test app container creation under the following circumstances:
// 1. An app is authorised for the first time with `app_container` set to `true`.
// 2. If an app is authorised for the first time with `app_container` set to `false`,
// then any subsequent authorisation with `app_container` set to `true` should trigger
// the creation of the app's own container.
// 3. If an app is authorised with `app_container` set to `true`, then subsequent
// authorisation should not use up any mutations.
// 4. Make sure that the app's own container is also created when it's re-authorised
// with `app_container` set to `true` after it's been revoked.
#[test]
#[allow(unsafe_code)]
fn app_container_creation() {
    // Authorise an app for the first time with `app_container` set to `true`.
    let auth = authenticator::create_account_and_login();

    let app_info = gen_app_exchange_info();
    let app_id = app_info.id.clone();
    let app = authorise_app(&auth, &app_info, &app_id, true);

    assert_eq!(num_containers(&app), 1); // should only contain app container

    // Authorise a new app with `app_container` set to `false`.
    let auth = authenticator::create_account_and_login();

    let app_info = gen_app_exchange_info();
    let app_id = app_info.id.clone();
    let mut app = authorise_app(&auth, &app_info, &app_id, false);

    assert_eq!(num_containers(&app), 0); // should be empty

    // Re-authorise the app with `app_container` set to `true`.
    app = authorise_app(&auth, &app_info, &app_id, true);

    assert_eq!(num_containers(&app), 1); // should only contain app container

    // Make sure no mutations are done when re-authorising the app now.
    let orig_balance: Coins = unwrap!(auth_run(&auth, |client| {
        client.get_balance(None).map_err(AuthError::from)
    }));

    let _ = authorise_app(&auth, &app_info, &app_id, true);

    let new_balance: Coins = unwrap!(auth_run(&auth, |client| {
        client.get_balance(None).map_err(AuthError::from)
    }));

    assert_eq!(orig_balance, new_balance);

    // Authorise a new app with `app_container` set to `false`.
    let auth = authenticator::create_account_and_login();

    let app_info = gen_app_exchange_info();
    let app_id = app_info.id.clone();
    let app = authorise_app(&auth, &app_info, &app_id, false);

    assert_eq!(num_containers(&app), 0); // should be empty

    // Revoke the app
    revoke(&auth, &app_id);

    // Re-authorise the app with `app_container` set to `true`.
    let app = authorise_app(&auth, &app_info, &app_id, true);

    assert_eq!(num_containers(&app), 1); // should only contain app container
}

// Test unregistered clients.
// 1. Have a registered clients put published immutable and published append-only data on the network.
// 2. Try to read them as unregistered.
#[test]
fn unregistered_client() {
    let addr: XorName = new_rand::random();
    let tag = 15002;
    let pub_idata = PubImmutableData::new(unwrap!(utils::generate_random_vector(30)));
    let pub_adata = PubUnseqAppendOnlyData::new(addr, tag);
    let unpub_adata = UnpubUnseqAppendOnlyData::new(addr, tag);

    // Registered Client PUTs something onto the network.
    {
        let pub_idata = pub_idata.clone();
        let mut pub_adata = pub_adata.clone();
        let mut unpub_adata = unpub_adata.clone();
        random_client(|client| {
            let owner = ADataOwner {
                public_key: unwrap!(client.owner_key()),
                entries_index: 0,
                permissions_index: 0,
            };
            unwrap!(pub_adata.append_owner(owner, 0));
            unwrap!(unpub_adata.append_owner(owner, 0));
            let client2 = client.clone();
            let client3 = client.clone();
            client
                .put_pub_idata(pub_idata)
                .and_then(move |_| client2.put_adata(pub_adata.into()))
                .and_then(move |_| client3.put_adata(unpub_adata.into()))
        });
    }

    // Unregistered Client should be able to retrieve the data.
    let app = unwrap!(App::unregistered(|| (), None));
    unwrap!(run(&app, move |client, _context| {
        let client2 = client.clone();
        let client3 = client.clone();

        client
            .get_pub_idata(*pub_idata.name())
            .and_then(move |data| {
                assert_eq!(data, pub_idata);
                client2
                    .get_adata(ADataAddress::PubUnseq { name: addr, tag })
                    .map(move |data| {
                        assert_eq!(data.address(), pub_adata.address());
                        assert_eq!(data.tag(), pub_adata.tag());
                    })
            })
            .then(move |_| {
                client3
                    .get_adata(ADataAddress::UnpubUnseq { name: addr, tag })
                    .then(|res| {
                        match res {
                            Err(CoreError::NewRoutingClientError(SndError::AccessDenied)) => (),
                            res => panic!("Unexpected result {:?}", res),
                        }
                        Ok(())
                    })
            })
    }));
}

// Test account usage statistics before and after a mutation.
#[test]
fn account_info() {
    // Create an app that can access the owner's coin balance.
    let mut app_auth_req = create_random_auth_req();
    app_auth_req.app_permissions = AppPermissions {
        transfer_coins: true,
    };

    let app = unwrap!(create_app_by_req(&app_auth_req));

    let orig_balance: Coins = unwrap!(run(&app, |client, _| {
        client.get_balance(None).map_err(AppError::from)
    }));

    unwrap!(run(&app, |client, _| {
        client
            .put_idata(PubImmutableData::new(vec![1, 2, 3]))
            .map_err(AppError::from)
    }));

    let new_balance: Coins = unwrap!(run(&app, |client, _| {
        client.get_balance(None).map_err(AppError::from)
    }));

    assert_eq!(
        new_balance,
        unwrap!(orig_balance.checked_sub(unwrap!(Coins::from_nano(1))))
    );
}
