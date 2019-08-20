// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::test_utils::{create_app, create_random_auth_req};
use crate::{run, App, AppError};
use futures::future::Future;
use safe_authenticator::test_utils::{create_authenticator, register_app};
use safe_authenticator::{run as auth_run, AuthError};
use safe_core::utils::test_utils::random_client;
use safe_core::{AuthActions, Client, CoreError, FutureExt};
use safe_nd::{
    AData, ADataAddress, ADataAppendOperation, ADataEntry, ADataIndex, ADataOwner,
    ADataPubPermissionSet, ADataPubPermissions, ADataUnpubPermissionSet, ADataUnpubPermissions,
    ADataUser, Error as SndError, PubSeqAppendOnlyData, PubUnseqAppendOnlyData, PublicKey,
    UnpubSeqAppendOnlyData, UnpubUnseqAppendOnlyData, XorName,
};
use std::collections::BTreeMap;
use std::sync::mpsc;
use std::thread;

// AD created by app. App lists its own sign_pk in owners field. Put should fail - Rejected at the client handlers.
// Should pass when it lists the owner's sign_pk instead.
#[test]
fn data_created_by_an_app() {
    let app = create_app();
    let name: XorName = new_rand::random();
    let tag = 15_002;
    let data: Vec<AData> = vec![
        PubSeqAppendOnlyData::new(name, tag).into(),
        UnpubSeqAppendOnlyData::new(name, tag).into(),
        PubUnseqAppendOnlyData::new(name, tag).into(),
        UnpubUnseqAppendOnlyData::new(name, tag).into(),
    ];
    for mut invalid_data in data {
        let variant = invalid_data.kind();
        let mut valid_data = invalid_data.clone();
        unwrap!(run(&app, move |client, _| {
            let client2 = client.clone();

            let app_key = client.public_key();
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
                .put_adata(invalid_data)
                .then(move |res| {
                    match res {
                        Err(CoreError::DataError(SndError::InvalidOwners)) => (),
                        Ok(_) => panic!("{:?}: Unexpected success", variant),
                        Err(err) => panic!("{:?}: Unexpected error {:?}", variant, err),
                    }
                    client2.put_adata(valid_data)
                })
                .map_err(AppError::from)
        }));
    }
}

// AD created by owner and given to a permitted App. Owner has listed that app is allowed to read and append.
// App tries to read - should pass. App tries to append - should pass. App tries to change
// permission to allow itself to update - should fail. Owner then allows the App to manage permissions.
// App give another key permissions to append - should pass.
#[test]
fn managing_permissions_for_an_app() {
    let app = create_app();
    let name: XorName = new_rand::random();
    let tag = 15_002;
    let data: Vec<AData> = vec![
        PubSeqAppendOnlyData::new(name, tag).into(),
        UnpubSeqAppendOnlyData::new(name, tag).into(),
        PubUnseqAppendOnlyData::new(name, tag).into(),
        UnpubUnseqAppendOnlyData::new(name, tag).into(),
    ];
    for mut adata in data {
        let variant = adata.kind();
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
            // Send the app's key to be added to the data's permission list
            unwrap!(app_key_tx.send(sign_pk));
            // Wait for the address of the data on the network
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
                    if address.is_seq() {
                        client2.append_seq_adata(
                            ADataAppendOperation { address, values },
                            entries.len() as u64,
                        )
                    } else {
                        client2.append_unseq_adata(ADataAppendOperation { address, values })
                    }
                })
                .and_then(move |()| {
                    if address.is_pub() {
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
                    } else {
                        let mut permissions = BTreeMap::new();
                        let _ = permissions
                            .insert(sign_pk, ADataUnpubPermissionSet::new(true, true, true));
                        client3.add_unpub_adata_permissions(
                            address,
                            ADataUnpubPermissions {
                                permissions,
                                entries_index: 4,
                                owners_index: 1,
                            },
                            1,
                        )
                    }
                })
                .then(move |res| {
                    match res {
                        // FIXME: we should expect only `AccessDenied` here, but due to
                        // a discrepancy in the way it's handled by mock/non-mock vaults we cover both errors
                        Err(CoreError::DataError(SndError::AccessDenied))
                        | Err(CoreError::DataError(SndError::InvalidPermissions)) => (),
                        res => panic!("{:?}: Unexpected result: {:?}", variant, res),
                    }
                    // Signal the client to allow access to the data
                    // and wait for the signal that access is granted
                    unwrap!(allow_app_tx.send(()));
                    unwrap!(app_allowed_rx.recv());
                    let random_app =
                        PublicKey::from(threshold_crypto::SecretKey::random().public_key());
                    if address.is_pub() {
                        let mut permissions = BTreeMap::new();
                        let _ = permissions.insert(
                            ADataUser::Key(sign_pk),
                            ADataPubPermissionSet::new(true, true),
                        );
                        let _ = permissions.insert(
                            ADataUser::Key(random_app),
                            ADataPubPermissionSet::new(true, None),
                        );
                        client4.add_pub_adata_permissions(
                            address,
                            ADataPubPermissions {
                                permissions,
                                entries_index: 4,
                                owners_index: 1,
                            },
                            2,
                        )
                    } else {
                        let mut permissions = BTreeMap::new();
                        let _ = permissions
                            .insert(sign_pk, ADataUnpubPermissionSet::new(true, true, true));
                        let _ = permissions
                            .insert(random_app, ADataUnpubPermissionSet::new(true, true, false));
                        client4.add_unpub_adata_permissions(
                            address,
                            ADataUnpubPermissions {
                                permissions,
                                entries_index: 4,
                                owners_index: 1,
                            },
                            2,
                        )
                    }
                    .map(move |()| address)
                })
                .and_then(move |address| {
                    let values = vec![ADataEntry::new(vec![4], vec![1, 2, 3])];
                    if address.is_seq() {
                        client5.append_seq_adata(ADataAppendOperation { address, values }, 4)
                    } else {
                        client5.append_unseq_adata(ADataAppendOperation { address, values })
                    }
                    .map(move |()| address)
                })
                .and_then(move |address| {
                    client6.get_adata_range(
                        address,
                        (ADataIndex::FromStart(0), ADataIndex::FromEnd(0)),
                    )
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

        let _handle = thread::spawn(move || {
            random_client(move |client| {
                let client2 = client.clone();
                let client3 = client.clone();
                let client4 = client.clone();

                // Wait for the app's key and add it to the data's permissions list
                let app_pk: PublicKey = unwrap!(app_key_rx.recv());

                let address = *adata.address();
                if address.is_pub() {
                    let mut permissions = BTreeMap::new();
                    let _ = permissions.insert(
                        ADataUser::Key(app_pk),
                        ADataPubPermissionSet::new(true, None),
                    );
                    unwrap!(adata.append_pub_permissions(
                        ADataPubPermissions {
                            permissions,
                            entries_index: 0,
                            owners_index: 0,
                        },
                        0
                    ));
                } else {
                    let mut permissions = BTreeMap::new();
                    let _ =
                        permissions.insert(app_pk, ADataUnpubPermissionSet::new(true, true, false));
                    unwrap!(adata.append_unpub_permissions(
                        ADataUnpubPermissions {
                            permissions,
                            entries_index: 0,
                            owners_index: 0,
                        },
                        0
                    ));
                }

                unwrap!(adata.append_owner(
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
                if adata.is_seq() {
                    unwrap!(adata.append_seq(entries, 0));
                } else {
                    unwrap!(adata.append_unseq(entries));
                }

                client
                    .list_auth_keys_and_version()
                    .and_then(move |(_, version)| {
                        client2.ins_auth_key(app_pk, Default::default(), version + 1)
                    })
                    .and_then(move |()| client3.put_adata(adata))
                    .and_then(move |()| {
                        // Send the address of the data
                        unwrap!(address_tx.send(address));
                        // Wait for the app's signal to give it data access
                        unwrap!(allow_app_rx.recv());
                        if address.is_pub() {
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
                        } else {
                            let mut permissions = BTreeMap::new();
                            let _ = permissions
                                .insert(app_pk, ADataUnpubPermissionSet::new(true, true, true));
                            client4.add_unpub_adata_permissions(
                                address,
                                ADataUnpubPermissions {
                                    permissions,
                                    entries_index: 4,
                                    owners_index: 1,
                                },
                                1,
                            )
                        }
                    })
                    // Signal that the app is allowed access to the data
                    .map(move |()| unwrap!(app_allowed_tx.send(())))
                    .map_err(AppError::from)
            })
        });
        unwrap!(finish_rx.recv());
    }
}

// AData created by a random client. A random application tries to read the data - should pass if data is published.
// The client adds the app's key to its list of apps and to the permissions list of the data
// giving it read and append permissions. The app should now be able and read and append to the data.
// The client then revokes the app by removing it from its list of authorised apps. The app should not
// be able to append to the data anymore. But it should still be able to read the data since if it is published.
// The client tries to delete the data. It should pass if the data is unpublished. Deleting published data should fail.
#[test]
#[ignore]
fn restricted_access_and_deletion() {
    let name: XorName = new_rand::random();
    let tag = 15_002;
    let data: Vec<AData> = vec![
        PubSeqAppendOnlyData::new(name, tag).into(),
        UnpubSeqAppendOnlyData::new(name, tag).into(),
        PubUnseqAppendOnlyData::new(name, tag).into(),
        UnpubUnseqAppendOnlyData::new(name, tag).into(),
    ];
    for mut adata in data {
        let variant = adata.kind();
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

            // Wait for the address of the data on the network
            let address: ADataAddress = unwrap!(address_rx.recv());
            client
                .get_adata(address)
                .then(move |res| {
                    match (res, address.is_pub()) {
                        (Ok(data), true) => {
                            assert_eq!(*data.address(), address);
                            assert_eq!(data.entries_index(), 3);
                        }
                        (Err(CoreError::DataError(SndError::AccessDenied)), false) => {}
                        (res, _) => panic!("{:?}: Unexpected result: {:?}", variant, res),
                    }
                    // Send the app's key so it can be authenticated and granted access to the data
                    // and wait for the signal that the operations are complete
                    unwrap!(app_key_tx.send(client2.public_key()));
                    unwrap!(app_authed_rx.recv());
                    client2.get_adata(address)
                })
                .and_then(move |data| {
                    assert_eq!(*data.address(), address);
                    assert_eq!(data.entries_index(), 3);
                    Ok(data.entries_index())
                })
                .and_then(move |index| {
                    let values = vec![ADataEntry::new(vec![3], vec![1, 2, 3])];
                    if address.is_seq() {
                        client3.append_seq_adata(ADataAppendOperation { address, values }, index)
                    } else {
                        client3.append_unseq_adata(ADataAppendOperation { address, values })
                    }
                    .map(move |()| index)
                })
                .and_then(move |index| {
                    // Signal the authenticator to revoke the app and wait for the signal that the
                    // operation is complete
                    unwrap!(revoke_app_tx.send(()));
                    unwrap!(app_revoked_rx.recv());
                    let values = vec![ADataEntry::new(vec![3], vec![1, 2, 3])];
                    if address.is_seq() {
                        client4.append_seq_adata(ADataAppendOperation { address, values }, index)
                    } else {
                        client4.append_unseq_adata(ADataAppendOperation { address, values })
                    }
                })
                .then(move |res| {
                    match res {
                        Err(CoreError::DataError(SndError::AccessDenied)) => (),
                        res => panic!("{:?}: Unexpected result: {:?}", variant, res),
                    }
                    client5.get_adata(address)
                })
                .then(move |res| {
                    match (res, address.is_pub()) {
                        (Ok(data), true) => assert_eq!(*data.address(), address),
                        (Err(CoreError::DataError(SndError::AccessDenied)), false) => {}
                        (res, _) => panic!("{:?}: Unexpected result: {:?}", variant, res),
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

                unwrap!(adata.append_owner(
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
                let address = *adata.address();
                if address.is_seq() {
                    unwrap!(adata.append_seq(entries, 0));
                } else {
                    unwrap!(adata.append_unseq(entries));
                }
                client
                    .put_adata(adata)
                    .and_then(move |()| {
                        // Send the address of the data on the network
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
                        if address.is_pub() {
                            let mut permissions = BTreeMap::new();
                            let _ = permissions.insert(
                                ADataUser::Key(key),
                                ADataPubPermissionSet::new(true, None),
                            );
                            client4.add_pub_adata_permissions(
                                address,
                                ADataPubPermissions {
                                    permissions,
                                    entries_index: 3,
                                    owners_index: 1,
                                },
                                0,
                            )
                        } else {
                            let mut permissions = BTreeMap::new();
                            let _ = permissions
                                .insert(key, ADataUnpubPermissionSet::new(true, true, false));
                            client4.add_unpub_adata_permissions(
                                address,
                                ADataUnpubPermissions {
                                    permissions,
                                    entries_index: 3,
                                    owners_index: 1,
                                },
                                0,
                            )
                        }
                        .map(move |()| (key, version))
                    })
                    .and_then(move |(key, version)| {
                        // Signal that the app has been authenticated
                        unwrap!(app_authed_tx.send(()));
                        // Wait for the signal to revoke the app
                        unwrap!(revoke_app_rx.recv());
                        client5.del_auth_key(key, version + 1)
                    })
                    .and_then(move |()| {
                        // Signal that the app is revoked
                        unwrap!(app_revoked_tx.send(()));
                        client6.delete_adata(address)
                    })
                    .then(move |res| {
                        match (res, address.is_pub()) {
                            (Err(CoreError::DataError(SndError::InvalidOperation)), true) => (),
                            (Ok(()), false) => (),
                            (res, _) => panic!("{:?}: Unexpected result: {:?}", variant, res),
                        }
                        Ok::<_, AuthError>(())
                    })
            }));
        });
        unwrap!(finish_rx.recv());
        unwrap!(handle.join());
    }
}

// A client publishes some data giving permissions for ANYONE to append to the data and an app to manage permissions.
// The app should be able to append to the permissions and entries list. Random clients should be able to append and read the entries.
// The client then specifically denies the application permission to append entries and permissions.
// The app attempts to append permissions and entries - should fail. App tries to read data - should pass.
// Random clients should still be able to read and append entries.
#[test]
fn public_permissions_with_app_restrictions() {
    let app = create_app();
    let name: XorName = new_rand::random();
    let tag = 15_002;
    let data: Vec<AData> = vec![
        PubSeqAppendOnlyData::new(name, tag).into(),
        PubUnseqAppendOnlyData::new(name, tag).into(),
    ];
    for mut adata in data {
        let variant = adata.kind();
        let (app_key_tx, app_key_rx) = mpsc::channel();
        let (address_tx, address_rx) = mpsc::channel();
        let (remove_app_tx, remove_app_rx) = mpsc::channel();
        let (app_removed_tx, app_removed_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();

        unwrap!(app.send(move |client, _| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();

            let app_key = client.public_key();
            // Send the app's key to grant it access to the data
            unwrap!(app_key_tx.send(app_key));
            // Wait for the address of the data on the network
            let address: ADataAddress = unwrap!(address_rx.recv());
            client
                .get_adata(address)
                .and_then(move |data| {
                    assert_eq!(*data.address(), address);
                    let values = vec![ADataEntry::new(vec![3], vec![1, 2, 3])];
                    if address.is_seq() {
                        client2.append_seq_adata(
                            ADataAppendOperation { address, values },
                            data.entries_index(),
                        )
                    } else {
                        client2.append_unseq_adata(ADataAppendOperation { address, values })
                    }
                })
                .and_then(move |()| {
                    let mut permissions = BTreeMap::new();
                    let random_app =
                        PublicKey::from(threshold_crypto::SecretKey::random().public_key());
                    let _ = permissions.insert(
                        ADataUser::Key(app_key),
                        ADataPubPermissionSet::new(true, true),
                    );
                    let _ = permissions.insert(
                        ADataUser::Key(random_app),
                        ADataPubPermissionSet::new(true, true),
                    );
                    let _ = permissions
                        .insert(ADataUser::Anyone, ADataPubPermissionSet::new(true, false));
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
                .and_then(move |()| {
                    random_app_access(address);
                    // Signal the client to remove the app from the data's permissions
                    // and wait for the signal that the operation is complete
                    unwrap!(remove_app_tx.send(()));
                    unwrap!(app_removed_rx.recv());
                    let values = vec![ADataEntry::new(vec![6], vec![1, 2, 3])];
                    if address.is_seq() {
                        client4.append_seq_adata(ADataAppendOperation { address, values }, 3)
                    } else {
                        client4.append_unseq_adata(ADataAppendOperation { address, values })
                    }
                })
                .then(move |res| {
                    match res {
                        Err(CoreError::DataError(SndError::AccessDenied)) => (),
                        res => panic!("{:?}: Unexpected result: {:?}", variant, res),
                    }
                    let permissions = BTreeMap::new();
                    client5.add_pub_adata_permissions(
                        address,
                        ADataPubPermissions {
                            permissions,
                            entries_index: 7,
                            owners_index: 1,
                        },
                        3,
                    )
                })
                .then(move |res| {
                    match res {
                        Err(CoreError::DataError(SndError::AccessDenied)) => (),
                        res => panic!("{:?}: Unexpected result: {:?}", variant, res),
                    }
                    client6.get_adata(address)
                })
                .then(move |res| {
                    let data = unwrap!(res);
                    assert_eq!(*data.address(), address);
                    random_app_access(address);
                    unwrap!(finish_tx.send(()));
                    Ok(())
                })
                .into_box()
                .into()
        }));

        let handle = thread::spawn(move || {
            random_client(move |client| {
                let client2 = client.clone();

                // Wait for the app's key and add it to the data's permission list
                let app_pk: PublicKey = unwrap!(app_key_rx.recv());

                let mut permissions = BTreeMap::new();
                let _ = permissions.insert(
                    ADataUser::Key(app_pk),
                    ADataPubPermissionSet::new(None, true),
                );
                let _ =
                    permissions.insert(ADataUser::Anyone, ADataPubPermissionSet::new(true, None));

                unwrap!(adata.append_pub_permissions(
                    ADataPubPermissions {
                        permissions,
                        entries_index: 0,
                        owners_index: 0,
                    },
                    0
                ));

                unwrap!(adata.append_owner(
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
                let address = *adata.address();
                if address.is_seq() {
                    unwrap!(adata.append_seq(entries, 0));
                } else {
                    unwrap!(adata.append_unseq(entries));
                }
                client
                    .put_adata(adata)
                    .and_then(move |()| {
                        // Send the address of the data on the network
                        unwrap!(address_tx.send(address));
                        // Wait for the signal to remove the app from the permissions list
                        unwrap!(remove_app_rx.recv());
                        let mut permissions = BTreeMap::new();
                        let _ = permissions.insert(
                            ADataUser::Key(app_pk),
                            ADataPubPermissionSet::new(false, false),
                        );
                        let _ = permissions
                            .insert(ADataUser::Anyone, ADataPubPermissionSet::new(true, false));
                        client2.add_pub_adata_permissions(
                            address,
                            ADataPubPermissions {
                                permissions,
                                entries_index: 5,
                                owners_index: 1,
                            },
                            2,
                        )
                    })
                    .and_then(move |()| {
                        // Signal that the app is removed from the permissions list
                        unwrap!(app_removed_tx.send(()));
                        Ok(())
                    })
            })
        });
        unwrap!(handle.join());
        unwrap!(finish_rx.recv());
    }
}

// Ensures that a random client has access to data at an address.
fn random_app_access(address: ADataAddress) {
    let handle = thread::spawn(move || {
        let random_app = create_app();
        unwrap!(run(&random_app, move |rand_client, _| {
            let rand_client2 = rand_client.clone();
            let rand_client3 = rand_client.clone();

            rand_client
                .get_adata(address)
                .and_then(move |data| {
                    assert_eq!(*data.address(), address);
                    let key: [u8; 5] = new_rand::random();
                    let values = vec![ADataEntry::new(key.to_vec(), vec![1, 2, 3])];
                    if address.is_seq() {
                        rand_client2.append_seq_adata(
                            ADataAppendOperation { address, values },
                            data.entries_index(),
                        )
                    } else {
                        rand_client2.append_unseq_adata(ADataAppendOperation { address, values })
                    }
                    .map(move |()| data.entries_index() + 1)
                })
                .and_then(move |index| {
                    rand_client3
                        .get_adata_range(
                            address,
                            (ADataIndex::FromStart(0), ADataIndex::FromEnd(0)),
                        )
                        .map(move |entries| (entries, index))
                })
                .and_then(move |(entries, index)| {
                    assert_eq!(entries.len() as u64, index);
                    Ok(())
                })
                .map_err(AppError::from)
        }));
    });
    unwrap!(handle.join());
}
