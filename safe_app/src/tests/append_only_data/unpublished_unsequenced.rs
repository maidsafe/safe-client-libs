// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::test_utils::{create_app, create_random_auth_req};
use crate::{run, App};
use futures::Future;
use safe_authenticator::test_utils::{create_authenticator, register_app};
use safe_authenticator::{run as auth_run, AuthError};
use safe_core::client::AuthActions;
use safe_core::utils::test_utils::random_client;
use safe_core::{Client, CoreError, FutureExt};
use safe_nd::{
    ADataAddress, ADataAppendOperation, ADataEntry, ADataIndex, ADataOwner,
    ADataUnpubPermissionSet, ADataUnpubPermissions, AppendOnlyData, Error as SndError, PublicKey,
    UnpubUnseqAppendOnlyData, UnseqAppendOnly, XorName,
};
use std::collections::BTreeMap;
use std::sync::mpsc;
use std::thread;

// AD created by app. App lists it's own sign_pk in owners field. Put should fail - Rejected at the client handlers.
// Should pass when it lists the owner's sign_pk instead.
#[test]
fn ad_created_by_app() {
    let app = create_app();
    unwrap!(run(&app, |client, _| {
        let client2 = client.clone();

        let app_key = client.public_key();
        let name: XorName = new_rand::random();
        let tag = 15_002;
        let mut invalid_data = UnpubUnseqAppendOnlyData::new(name, tag);
        let mut valid_data = invalid_data.clone();
        unwrap!(invalid_data.append_owner(
            ADataOwner {
                public_key: app_key,
                entries_index: 0,
                permissions_index: 0,
            },
            0
        ));
        unwrap!(valid_data.append_owner(
            ADataOwner {
                public_key: client.owner_key(),
                entries_index: 0,
                permissions_index: 0,
            },
            0
        ));
        client
            .put_adata(invalid_data.into())
            .then(move |res| {
                match res {
                    Err(CoreError::NewRoutingClientError(SndError::InvalidOwners)) => (),
                    Ok(_) => panic!("Unexpected success"),
                    Err(err) => panic!("Unexpected error {:?}", err),
                }
                client2.put_adata(valid_data.into())
            })
            .map_err(|e| panic!("{:?}", e))
    }));
}

// AD created by owner and given to a permitted App. Owner has listed that app is allowed to read
// only. App tries to read - should pass. App tries to append - should fail. App tries to change
// permission to allow itself to update - should fail. Owner then allows the App to manage permissions.
// App gives itself append permissions - should pass and be able to append entries.
#[test]
fn managing_permissions_for_an_app() {
    let app = create_app();
    let (app_key_tx, app_key_rx) = mpsc::channel();
    let (address_tx, address_rx) = mpsc::channel();
    let (allow_app_tx, allow_app_rx) = mpsc::channel();
    let (app_allowed_tx, app_allowed_rx) = mpsc::channel();
    let (finish_tx, finish_rx) = mpsc::channel();

    unwrap!(app.send(move |client, _| {
        let client2 = client.clone();
        let client3 = client.clone();
        let client4 = client.clone();
        let client5 = client.clone();
        let client6 = client.clone();

        let sign_pk = client.public_key();
        unwrap!(app_key_tx.send(sign_pk));
        let address: ADataAddress = unwrap!(address_rx.recv());
        client
            .get_adata_range(address, (ADataIndex::FromStart(0), ADataIndex::FromEnd(0)))
            .and_then(move |entries| {
                let expected_entries = vec![
                    ADataEntry::new(vec![0], vec![1, 2, 3]),
                    ADataEntry::new(vec![1], vec![1, 2, 3]),
                    ADataEntry::new(vec![2], vec![1, 2, 3]),
                ];
                assert_eq!(entries.len(), expected_entries.len());
                assert_eq!(entries, expected_entries);
                let values = vec![ADataEntry::new(vec![3], vec![1, 2, 3])];
                client2.append_unseq_adata(ADataAppendOperation { address, values })
            })
            .then(move |res| {
                match res {
                    Err(CoreError::NewRoutingClientError(SndError::AccessDenied)) => (),
                    res => panic!("Unexpected result: {:?}", res),
                }
                let mut permissions = BTreeMap::new();
                let _ = permissions.insert(sign_pk, ADataUnpubPermissionSet::new(true, true, true));
                client3.add_unpub_adata_permissions(
                    address,
                    ADataUnpubPermissions {
                        permissions,
                        entries_index: 3,
                        owners_index: 1,
                    },
                    1,
                )
            })
            .then(move |res| {
                match res {
                    Err(CoreError::NewRoutingClientError(SndError::AccessDenied)) => (),
                    res => panic!("Unexpected result: {:?}", res),
                }
                unwrap!(allow_app_tx.send(()));
                unwrap!(app_allowed_rx.recv());
                let mut permissions = BTreeMap::new();
                let _ = permissions.insert(sign_pk, ADataUnpubPermissionSet::new(true, true, true));
                client4
                    .add_unpub_adata_permissions(
                        address,
                        ADataUnpubPermissions {
                            permissions,
                            entries_index: 3,
                            owners_index: 1,
                        },
                        2,
                    )
                    .map(move |()| address)
            })
            .and_then(move |address| {
                let values = vec![ADataEntry::new(vec![3], vec![1, 2, 3])];
                client5
                    .append_unseq_adata(ADataAppendOperation { address, values })
                    .map(move |()| address)
            })
            .and_then(move |address| {
                client6.get_adata_range(address, (ADataIndex::FromStart(0), ADataIndex::FromEnd(0)))
            })
            .then(move |res| {
                let entries = unwrap!(res);
                assert_eq!(entries.len(), 4);
                unwrap!(finish_tx.send(()));
                Ok(())
            })
            .into_box()
            .into()
    }));

    let _handle = thread::spawn(|| {
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();

            let app_pk: PublicKey = unwrap!(app_key_rx.recv());

            let mut permissions = BTreeMap::new();
            let _ = permissions.insert(app_pk, ADataUnpubPermissionSet::new(true, false, false));
            let name: XorName = new_rand::random();
            let tag = 15_002;
            let mut data = UnpubUnseqAppendOnlyData::new(name, tag);
            let address = *data.address();

            unwrap!(data.append_permissions(
                ADataUnpubPermissions {
                    permissions: permissions,
                    entries_index: 0,
                    owners_index: 0,
                },
                0
            ));

            unwrap!(data.append_owner(
                ADataOwner {
                    public_key: client.owner_key(),
                    entries_index: 0,
                    permissions_index: 1,
                },
                0
            ));

            let entries = vec![
                ADataEntry::new(vec![0], vec![1, 2, 3]),
                ADataEntry::new(vec![1], vec![1, 2, 3]),
                ADataEntry::new(vec![2], vec![1, 2, 3]),
            ];

            unwrap!(data.append(entries));

            client
                .list_auth_keys_and_version()
                .and_then(move |(_, version)| {
                    client2.ins_auth_key(app_pk, Default::default(), version + 1)
                })
                .and_then(move |()| client3.put_adata(data.into()))
                .and_then(move |()| {
                    unwrap!(address_tx.send(address));
                    unwrap!(allow_app_rx.recv());
                    let mut permissions = BTreeMap::new();
                    let _ = permissions
                        .insert(app_pk, ADataUnpubPermissionSet::new(false, false, true));
                    client4.add_unpub_adata_permissions(
                        address,
                        ADataUnpubPermissions {
                            permissions,
                            entries_index: 3,
                            owners_index: 1,
                        },
                        1,
                    )
                })
                .map(move |()| unwrap!(app_allowed_tx.send(())))
                .map_err(|e| panic!("{:?}", e))
        })
    });
    unwrap!(finish_rx.recv());
}

// AData created by a random client. A random application tries to read the data - should fail.
// The client adds the app's key to it's list of apps and to the permissions list of the data
// giving it read and append permissions. The app should now be able read the data and append to it.
// The client then revokes the app by removing it from it's list of authorised apps. The app should not
// be able to access the data anymore. The client then deletes the data from the network and tries to read it.
// It should fail with a no such data error.
#[test]
fn restricted_access_and_deletion() {
    let (address_tx, address_rx) = mpsc::channel();
    let (app_key_tx, app_key_rx) = mpsc::channel();
    let (app_authed_tx, app_authed_rx) = mpsc::channel();
    let (revoke_app_tx, revoke_app_rx) = mpsc::channel();
    let (app_revoked_tx, app_revoked_rx) = mpsc::channel();
    let (finish_tx, finish_rx) = mpsc::channel();

    let (authenticator, _, _) = create_authenticator();
    let auth_req = create_random_auth_req();
    let auth_granted = unwrap!(register_app(&authenticator, &auth_req));
    let app = unwrap!(App::registered(auth_req.app.id, auth_granted, || ()));
    unwrap!(app.send(move |client, _| {
        let client2 = client.clone();
        let client3 = client.clone();
        let client4 = client.clone();

        let address: ADataAddress = unwrap!(address_rx.recv());
        client
            .get_adata(address)
            .then(move |res| {
                match res {
                    Err(CoreError::NewRoutingClientError(SndError::AccessDenied)) => (),
                    res => panic!("Unexpected result: {:?}", res),
                }
                unwrap!(app_key_tx.send(client2.public_key()));
                unwrap!(app_authed_rx.recv());
                Ok(())
            })
            .and_then(move |()| client3.get_adata(address))
            .and_then(move |data| {
                assert_eq!(*data.address(), address);
                unwrap!(revoke_app_tx.send(()));
                unwrap!(app_revoked_rx.recv());
                client4.get_adata(address)
            })
            .then(move |res| {
                match res {
                    Err(CoreError::NewRoutingClientError(SndError::AccessDenied)) => (),
                    res => panic!("Unexpected result: {:?}", res),
                }
                unwrap!(finish_tx.send(()));
                Ok(())
            })
            .into_box()
            .into()
    }));

    let handle = thread::spawn(move || {
        unwrap!(auth_run(&authenticator, move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();
            let client7 = client.clone();

            let name: XorName = new_rand::random();
            let tag = 15_002;
            let mut data = UnpubUnseqAppendOnlyData::new(name, tag);
            unwrap!(data.append_owner(
                ADataOwner {
                    public_key: client.owner_key(),
                    entries_index: 0,
                    permissions_index: 0,
                },
                0
            ));
            let entries = vec![
                ADataEntry::new(vec![0], vec![1, 2, 3]),
                ADataEntry::new(vec![1], vec![1, 2, 3]),
                ADataEntry::new(vec![2], vec![1, 2, 3]),
            ];
            unwrap!(data.append(entries));
            let address = *data.address();
            client
                .put_adata(data.into())
                .and_then(move |()| {
                    unwrap!(address_tx.send(address));
                    client2.list_auth_keys_and_version()
                })
                .and_then(move |(_, version)| {
                    let app_key: PublicKey = unwrap!(app_key_rx.recv());
                    client3
                        .ins_auth_key(app_key, Default::default(), version + 1)
                        .map(move |()| (app_key, version + 1))
                })
                .and_then(move |(key, version)| {
                    let mut permissions = BTreeMap::new();
                    let _ =
                        permissions.insert(key, ADataUnpubPermissionSet::new(true, false, false));
                    client4
                        .add_unpub_adata_permissions(
                            address,
                            ADataUnpubPermissions {
                                permissions,
                                entries_index: 3,
                                owners_index: 1,
                            },
                            0,
                        )
                        .map(move |()| (key, version))
                })
                .and_then(move |(key, version)| {
                    unwrap!(app_authed_tx.send(()));
                    unwrap!(revoke_app_rx.recv());
                    client5.del_auth_key(key, version + 1)
                })
                .and_then(move |()| {
                    unwrap!(app_revoked_tx.send(()));
                    client6.delete_adata(address)
                })
                .and_then(move |()| client7.get_adata(address))
                .then(|res| {
                    match res {
                        Err(CoreError::NewRoutingClientError(SndError::NoSuchData)) => (),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    Ok::<_, AuthError>(())
                })
        }));
    });
    unwrap!(finish_rx.recv());
    unwrap!(handle.join());
}
