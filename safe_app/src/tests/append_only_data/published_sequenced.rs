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
    ADataAddress, ADataAppendOperation, ADataEntry, ADataIndex, ADataOwner, ADataPubPermissionSet,
    ADataPubPermissions, ADataUser, AppendOnlyData, Error as SndError, PubSeqAppendOnlyData,
    PublicKey, SeqAppendOnly, XorName,
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
        let mut invalid_data = PubSeqAppendOnlyData::new(name, tag);
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

// AD created by owner and given to a permitteds App. Owner has listed that app is allowed to append
// only. App tries to read - should pass. App tries to append - should pass. App tries to change
// permission to allow itself to update - should fail. Owner then allows the App to manage permissions.
// App give another key permissions to append - should pass.
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
                client2.append_seq_adata(
                    ADataAppendOperation { address, values },
                    entries.len() as u64,
                )
            })
            .and_then(move |()| {
                let mut permissions = BTreeMap::new();
                let _ = permissions.insert(
                    ADataUser::Key(sign_pk),
                    ADataPubPermissionSet::new(true, true),
                );
                client3.add_pub_adata_permissions(
                    address,
                    ADataPubPermissions {
                        permissions,
                        entries_index: 4,
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
                let random_app =
                    PublicKey::from(threshold_crypto::SecretKey::random().public_key());
                let _ = permissions.insert(
                    ADataUser::Key(sign_pk),
                    ADataPubPermissionSet::new(true, true),
                );
                let _ = permissions.insert(
                    ADataUser::Key(random_app),
                    ADataPubPermissionSet::new(true, false),
                );
                client4
                    .add_pub_adata_permissions(
                        address,
                        ADataPubPermissions {
                            permissions,
                            entries_index: 4,
                            owners_index: 1,
                        },
                        2,
                    )
                    .map(move |()| address)
            })
            .and_then(move |address| {
                let values = vec![ADataEntry::new(vec![4], vec![1, 2, 3])];
                client5
                    .append_seq_adata(ADataAppendOperation { address, values }, 4)
                    .map(move |()| address)
            })
            .and_then(move |address| {
                client6.get_adata_range(address, (ADataIndex::FromStart(0), ADataIndex::FromEnd(0)))
            })
            .then(move |res| {
                let entries = unwrap!(res);
                assert_eq!(entries.len(), 5);
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
            let _ = permissions.insert(
                ADataUser::Key(app_pk),
                ADataPubPermissionSet::new(true, false),
            );
            let name: XorName = new_rand::random();
            let tag = 15_002;
            let mut data = PubSeqAppendOnlyData::new(name, tag);
            let address = *data.address();

            unwrap!(data.append_permissions(
                ADataPubPermissions {
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

            unwrap!(data.append(entries, 0));

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
                    let _ = permissions.insert(
                        ADataUser::Key(app_pk),
                        ADataPubPermissionSet::new(true, true),
                    );
                    client4.add_pub_adata_permissions(
                        address,
                        ADataPubPermissions {
                            permissions,
                            entries_index: 4,
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

// AData created by a random client. A random application tries to read the data - should pass.
// The client adds the app's key to it's list of apps and to the permissions list of the data
// giving it append permissions. The app should now be able and append to the data.
// The client then revokes the app by removing it from it's list of authorised apps. The app should not
// be able to append to the data anymore. But it should still be able to read the data since it is published.
// The client tries to delete the data. It should fail since it's an invalid operation
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
        let client5 = client.clone();

        let address: ADataAddress = unwrap!(address_rx.recv());
        client
            .get_adata(address)
            .and_then(move |data| {
                assert_eq!(*data.address(), address);
                assert_eq!(data.entries_index(), 3);
                unwrap!(app_key_tx.send(client2.public_key()));
                unwrap!(app_authed_rx.recv());
                Ok(data.entries_index())
            })
            .and_then(move |index| {
                let values = vec![ADataEntry::new(vec![3], vec![1, 2, 3])];
                client3
                    .append_seq_adata(ADataAppendOperation { address, values }, index)
                    .map(move |()| index)
            })
            .and_then(move |index| {
                unwrap!(revoke_app_tx.send(()));
                unwrap!(app_revoked_rx.recv());
                let values = vec![ADataEntry::new(vec![3], vec![1, 2, 3])];
                client4.append_seq_adata(ADataAppendOperation { address, values }, index)
            })
            .then(move |res| {
                match res {
                    Err(CoreError::NewRoutingClientError(SndError::AccessDenied)) => (),
                    res => panic!("Unexpected result: {:?}", res),
                }
                client5.get_adata(address)
            })
            .then(move |res| {
                let data = unwrap!(res);
                assert_eq!(*data.address(), address);
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

            let name: XorName = new_rand::random();
            let tag = 15_002;
            let mut data = PubSeqAppendOnlyData::new(name, tag);
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
            unwrap!(data.append(entries, 0));
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
                    let _ = permissions
                        .insert(ADataUser::Key(key), ADataPubPermissionSet::new(true, false));
                    client4
                        .add_pub_adata_permissions(
                            address,
                            ADataPubPermissions {
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
                .then(|res| {
                    match res {
                        Err(CoreError::NewRoutingClientError(SndError::InvalidOperation)) => (),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    Ok::<_, AuthError>(())
                })
        }));
    });
    unwrap!(finish_rx.recv());
    unwrap!(handle.join());
}
