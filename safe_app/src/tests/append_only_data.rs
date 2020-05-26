// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::test_utils::{create_app, create_random_auth_req};
use crate::{App, AppError};
use log::trace;
use safe_authenticator::test_utils::{create_authenticator, register_app};
use safe_core::utils::test_utils::random_client;
use safe_core::{AuthActions, Client, CoreError};
use safe_nd::{
    AData, ADataAddress, ADataAppendOperation, ADataEntry, ADataIndex, ADataOwner,
    ADataPubPermissionSet, ADataPubPermissions, ADataUnpubPermissionSet, ADataUnpubPermissions,
    ADataUser, AppPermissions, Error as SndError, PubSeqAppendOnlyData, PubUnseqAppendOnlyData,
    PublicKey, UnpubSeqAppendOnlyData, UnpubUnseqAppendOnlyData, XorName,
};
use std::collections::BTreeMap;
use tokio::{sync::mpsc, task::LocalSet};

// AD created by app. App lists its own public key in owners field. Put should fail - Rejected at
// the client handlers. Should pass when it lists the owner's public key instead.
#[tokio::test]
async fn data_created_by_an_app() -> Result<(), AppError> {
    let app = create_app().await;
    let name: XorName = rand::random();
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
        let client = app.client.clone();

        let app_key = client.public_key().await;
        invalid_data.append_owner(
            ADataOwner {
                public_key: app_key,
                entries_index: 0,
                permissions_index: 0,
            },
            0,
        )?;
        valid_data.append_owner(
            ADataOwner {
                public_key: client.owner_key().await,
                entries_index: 0,
                permissions_index: 0,
            },
            0,
        )?;
        match client.put_adata(invalid_data).await {
            Err(CoreError::DataError(SndError::InvalidOwners)) => (),
            Ok(_) => panic!("{:?}: Unexpected success", variant),
            Err(err) => panic!("{:?}: Unexpected error {:?}", variant, err),
        }
        client.put_adata(valid_data).await?;
    }
    Ok(())
}

// AD created by owner and given to a permitted App. Owner has listed that app is allowed to read and append.
// App tries to read - should pass. App tries to append - should pass. App tries to change
// permission to allow itself to update - should fail. Owner then allows the App to manage permissions.
// App give another key permissions to append - should pass.
#[tokio::test]
async fn managing_permissions_for_an_app() -> Result<(), AppError> {
    let app = create_app().await;
    let name: XorName = rand::random();
    let tag = 15_002;
    let data: Vec<AData> = vec![
        PubSeqAppendOnlyData::new(name, tag).into(),
        UnpubSeqAppendOnlyData::new(name, tag).into(),
        PubUnseqAppendOnlyData::new(name, tag).into(),
        UnpubUnseqAppendOnlyData::new(name, tag).into(),
    ];

    for mut adata in data {
        let (mut app_key_tx, mut app_key_rx) = mpsc::channel(1);
        let (mut address_tx, mut address_rx) = mpsc::channel(1);
        let (mut allow_app_tx, mut allow_app_rx) = mpsc::channel(1);
        let (mut app_allowed_tx, mut app_allowed_rx) = mpsc::channel(1);

        let client = app.client.clone();
        let app_pk = client.public_key().await;
        let variant = adata.kind();

        let local = LocalSet::new();
        let _ = local.spawn_local(async move {
            // Send the app's key to be added to the data's permission list
            app_key_tx
                .send(app_pk)
                .await
                .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;
            // Wait for the address of the data on the network
            let address: ADataAddress = address_rx.recv().await.ok_or_else(|| {
                CoreError::Unexpected("failed to receive from channel".to_string())
            })?;
            let entries = client
                .get_adata_range(address, (ADataIndex::FromStart(0), ADataIndex::FromEnd(0)))
                .await?;
            let expected_entries = vec![
                ADataEntry::new(vec![0], vec![1, 2, 3]),
                ADataEntry::new(vec![1], vec![1, 2, 3]),
                ADataEntry::new(vec![2], vec![1, 2, 3]),
            ];
            assert_eq!(entries.len(), expected_entries.len());
            assert_eq!(entries, expected_entries);
            let values = vec![ADataEntry::new(vec![3], vec![1, 2, 3])];
            if address.is_seq() {
                client
                    .append_seq_adata(
                        ADataAppendOperation { address, values },
                        entries.len() as u64,
                    )
                    .await?;
            } else {
                client
                    .append_unseq_adata(ADataAppendOperation { address, values })
                    .await?;
            }

            let res = if address.is_pub() {
                let mut permissions = BTreeMap::new();
                let _ = permissions.insert(
                    ADataUser::Key(app_pk),
                    ADataPubPermissionSet::new(true, true),
                );
                client
                    .add_pub_adata_permissions(
                        address,
                        ADataPubPermissions {
                            permissions,
                            entries_index: 4,
                            owners_index: 1,
                        },
                        1,
                    )
                    .await
            } else {
                let mut permissions = BTreeMap::new();
                let _ = permissions.insert(app_pk, ADataUnpubPermissionSet::new(true, true, true));
                client
                    .add_unpub_adata_permissions(
                        address,
                        ADataUnpubPermissions {
                            permissions,
                            entries_index: 4,
                            owners_index: 1,
                        },
                        1,
                    )
                    .await
            };

            match res {
                Err(CoreError::DataError(SndError::AccessDenied)) => (),
                res => panic!("{:?}: Unexpected result: {:?}", variant, res),
            }
            // Signal the client to allow access to the data
            // and wait for the signal that access is granted
            allow_app_tx
                .send(())
                .await
                .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;
            app_allowed_rx.recv().await.ok_or_else(|| {
                CoreError::Unexpected("failed to receive from channel".to_string())
            })?;
            let random_app = PublicKey::from(threshold_crypto::SecretKey::random().public_key());
            if address.is_pub() {
                let mut permissions = BTreeMap::new();
                let _ = permissions.insert(
                    ADataUser::Key(app_pk),
                    ADataPubPermissionSet::new(true, true),
                );
                let _ = permissions.insert(
                    ADataUser::Key(random_app),
                    ADataPubPermissionSet::new(true, None),
                );
                client
                    .add_pub_adata_permissions(
                        address,
                        ADataPubPermissions {
                            permissions,
                            entries_index: 4,
                            owners_index: 1,
                        },
                        2,
                    )
                    .await?;
            } else {
                let mut permissions = BTreeMap::new();
                let _ = permissions.insert(app_pk, ADataUnpubPermissionSet::new(true, true, true));
                let _ =
                    permissions.insert(random_app, ADataUnpubPermissionSet::new(true, true, false));
                client
                    .add_unpub_adata_permissions(
                        address,
                        ADataUnpubPermissions {
                            permissions,
                            entries_index: 4,
                            owners_index: 1,
                        },
                        2,
                    )
                    .await?;
            }
            let values = vec![ADataEntry::new(vec![4], vec![1, 2, 3])];
            if address.is_seq() {
                client
                    .append_seq_adata(ADataAppendOperation { address, values }, 4)
                    .await?;
            } else {
                client
                    .append_unseq_adata(ADataAppendOperation { address, values })
                    .await?;
            }
            let entries = client
                .get_adata_range(address, (ADataIndex::FromStart(0), ADataIndex::FromEnd(0)))
                .await?;
            assert_eq!(entries.len(), 5);

            Ok::<(), AppError>(())
        });

        let _ = local.spawn_local(async move {
            let client = random_client()?;

            // Wait for the app's key and add it to the data's permissions list
            let app_pk: PublicKey = app_key_rx.recv().await.ok_or_else(|| {
                CoreError::Unexpected("failed to receive from channel".to_string())
            })?;

            let address = *adata.address();
            if address.is_pub() {
                let mut permissions = BTreeMap::new();
                let _ = permissions.insert(
                    ADataUser::Key(app_pk),
                    ADataPubPermissionSet::new(true, None),
                );
                adata.append_pub_permissions(
                    ADataPubPermissions {
                        permissions,
                        entries_index: 0,
                        owners_index: 0,
                    },
                    0,
                )?;
            } else {
                let mut permissions = BTreeMap::new();
                let _ = permissions.insert(app_pk, ADataUnpubPermissionSet::new(true, true, false));
                adata.append_unpub_permissions(
                    ADataUnpubPermissions {
                        permissions,
                        entries_index: 0,
                        owners_index: 0,
                    },
                    0,
                )?;
            }

            adata.append_owner(
                ADataOwner {
                    public_key: client.owner_key().await,
                    entries_index: 0,
                    permissions_index: 1,
                },
                0,
            )?;

            let entries = vec![
                ADataEntry::new(vec![0], vec![1, 2, 3]),
                ADataEntry::new(vec![1], vec![1, 2, 3]),
                ADataEntry::new(vec![2], vec![1, 2, 3]),
            ];
            if adata.is_seq() {
                adata.append_seq(entries, 0)?;
            } else {
                adata.append_unseq(entries)?;
            }

            let (_, version) = client.list_auth_keys_and_version().await?;
            client
                .ins_auth_key(app_pk, Default::default(), version + 1)
                .await?;
            client.put_adata(adata).await?;
            // Send the address of the data
            address_tx
                .send(address)
                .await
                .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;
            // Wait for the app's signal to give it data access
            allow_app_rx.recv().await.ok_or_else(|| {
                CoreError::Unexpected("failed to receive from channel".to_string())
            })?;
            if address.is_pub() {
                let mut permissions = BTreeMap::new();
                let _ = permissions.insert(
                    ADataUser::Key(app_pk),
                    ADataPubPermissionSet::new(true, true),
                );
                client
                    .add_pub_adata_permissions(
                        address,
                        ADataPubPermissions {
                            permissions,
                            entries_index: 4,
                            owners_index: 1,
                        },
                        1,
                    )
                    .await?;
            } else {
                let mut permissions = BTreeMap::new();
                let _ = permissions.insert(app_pk, ADataUnpubPermissionSet::new(true, true, true));
                client
                    .add_unpub_adata_permissions(
                        address,
                        ADataUnpubPermissions {
                            permissions,
                            entries_index: 4,
                            owners_index: 1,
                        },
                        1,
                    )
                    .await?;
            }
            // Signal that the app is allowed access to the data
            app_allowed_tx
                .send(())
                .await
                .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;

            Ok::<(), AppError>(())
        });

        local.await;
    }
    Ok(())
}

// AData created by a random client. A random application tries to read the data - should pass if data is published.
// The client adds the app's key to its list of apps and to the permissions list of the data
// giving it read and append permissions. The app should now be able and read and append to the data.
// The client then revokes the app by removing it from its list of authorised apps. The app should not
// be able to append to the data anymore. But it should still be able to read the data since if it is published.
// The client tries to delete the data. It should pass if the data is unpublished. Deleting published data should fail.
#[tokio::test]
async fn restricted_access_and_deletion() -> Result<(), AppError> {
    let name: XorName = rand::random();
    let tag = 15_002;
    let data: Vec<AData> = vec![
        PubSeqAppendOnlyData::new(name, tag).into(),
        UnpubSeqAppendOnlyData::new(name, tag).into(),
        PubUnseqAppendOnlyData::new(name, tag).into(),
        UnpubUnseqAppendOnlyData::new(name, tag).into(),
    ];
    for mut adata in data {
        let (mut address_tx, mut address_rx) = mpsc::channel(1);
        let (mut app_key_tx, mut app_key_rx) = mpsc::channel(1);
        let (mut app_authed_tx, mut app_authed_rx) = mpsc::channel(1);
        let (mut revoke_app_tx, mut revoke_app_rx) = mpsc::channel(1);
        let (mut app_revoked_tx, mut app_revoked_rx) = mpsc::channel(1);

        let variant = adata.kind();

        let (authenticator, _, _) = create_authenticator().await;
        let auth_req = create_random_auth_req();
        let auth_granted = register_app(&authenticator, &auth_req)
            .await
            .map_err(|_| AppError::Unexpected("failed to create registered app".to_string()))?;
        let app = App::registered(auth_req.app.id, auth_granted, || ()).await?;
        let client = app.client;

        let local = LocalSet::new();
        let _ = local.spawn_local(async move {
            // Wait for the address of the data on the network
            let address: ADataAddress = address_rx.recv().await.ok_or_else(|| {
                CoreError::Unexpected("failed to receive from channel".to_string())
            })?;
            let res = client.get_adata(address).await;
            trace!("Got AData: {:?}", res);
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
            trace!("Authenticating app's key");
            app_key_tx
                .send(client.public_key().await)
                .await
                .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;
            app_authed_rx.recv().await.ok_or_else(|| {
                CoreError::Unexpected("failed to receive from channel".to_string())
            })?;
            trace!("App authenticated");

            let data = client.get_adata(address).await?;
            trace!("Got AData: {:?}", data);

            assert_eq!(*data.address(), address);
            assert_eq!(data.entries_index(), 3);
            let index = data.entries_index();
            let values = vec![ADataEntry::new(vec![3], vec![1, 2, 3])];
            if address.is_seq() {
                client
                    .append_seq_adata(ADataAppendOperation { address, values }, index)
                    .await?;
            } else {
                client
                    .append_unseq_adata(ADataAppendOperation { address, values })
                    .await?;
            }
            // Signal the authenticator to revoke the app and wait for the signal that the
            // operation is complete
            revoke_app_tx
                .send(())
                .await
                .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;
            app_revoked_rx.recv().await.ok_or_else(|| {
                CoreError::Unexpected("failed to receive from channel".to_string())
            })?;
            let values = vec![ADataEntry::new(vec![3], vec![1, 2, 3])];
            let res = if address.is_seq() {
                client
                    .append_seq_adata(ADataAppendOperation { address, values }, index)
                    .await
            } else {
                client
                    .append_unseq_adata(ADataAppendOperation { address, values })
                    .await
            };
            match res {
                Err(CoreError::DataError(SndError::AccessDenied)) => (),
                res => panic!("{:?}: Unexpected result: {:?}", variant, res),
            }

            match (client.get_adata(address).await, address.is_pub()) {
                (Ok(data), true) => assert_eq!(*data.address(), address),
                (Err(CoreError::DataError(SndError::AccessDenied)), false) => {}
                (res, _) => panic!("{:?}: Unexpected result: {:?}", variant, res),
            }

            Ok::<(), CoreError>(())
        });

        let _ = local.spawn_local(async move {
            let client = authenticator.client;

            adata.append_owner(
                ADataOwner {
                    public_key: client.owner_key().await,
                    entries_index: 0,
                    permissions_index: 0,
                },
                0,
            )?;
            let entries = vec![
                ADataEntry::new(vec![0], vec![1, 2, 3]),
                ADataEntry::new(vec![1], vec![1, 2, 3]),
                ADataEntry::new(vec![2], vec![1, 2, 3]),
            ];
            let address = *adata.address();
            if address.is_seq() {
                adata.append_seq(entries, 0)?;
            } else {
                adata.append_unseq(entries)?;
            }
            client.put_adata(adata).await?;
            // Send the address of the data on the network
            address_tx
                .send(address)
                .await
                .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;
            let (_, mut version) = client.list_auth_keys_and_version().await?;
            let app_key: PublicKey = app_key_rx.recv().await.ok_or_else(|| {
                CoreError::Unexpected("failed to receive from channel".to_string())
            })?;
            client
                .ins_auth_key(
                    app_key,
                    AppPermissions {
                        transfer_coins: true,
                        perform_mutations: true,
                        get_balance: true,
                    },
                    version + 1,
                )
                .await?;
            version += 1;
            if address.is_pub() {
                let mut permissions = BTreeMap::new();
                let _ = permissions.insert(
                    ADataUser::Key(app_key),
                    ADataPubPermissionSet::new(true, None),
                );
                client
                    .add_pub_adata_permissions(
                        address,
                        ADataPubPermissions {
                            permissions,
                            entries_index: 3,
                            owners_index: 1,
                        },
                        0,
                    )
                    .await?;
            } else {
                let mut permissions = BTreeMap::new();
                let _ =
                    permissions.insert(app_key, ADataUnpubPermissionSet::new(true, true, false));
                client
                    .add_unpub_adata_permissions(
                        address,
                        ADataUnpubPermissions {
                            permissions,
                            entries_index: 3,
                            owners_index: 1,
                        },
                        0,
                    )
                    .await?;
            }
            // Signal that the app has been authenticated
            app_authed_tx
                .send(())
                .await
                .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;
            // Wait for the signal to revoke the app
            revoke_app_rx.recv().await.ok_or_else(|| {
                CoreError::Unexpected("failed to receive from channel".to_string())
            })?;
            client.del_auth_key(app_key, version + 1).await?;
            // Signal that the app is revoked
            app_revoked_tx
                .send(())
                .await
                .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;
            match (client.delete_adata(address).await, address.is_pub()) {
                (Err(CoreError::DataError(SndError::InvalidOperation)), true) => (),
                (Ok(()), false) => (),
                (res, _) => panic!("{:?}: Unexpected result: {:?}", variant, res),
            }

            Ok::<(), AppError>(())
        });

        local.await;
    }
    Ok(())
}

// A client publishes some data giving permissions for ANYONE to append to the data and an app to manage permissions.
// The app should be able to append to the permissions and entries list. Random clients should be able to append and read the entries.
// The client then specifically denies the application permission to append entries and permissions.
// The app attempts to append permissions and entries - should fail. App tries to read data - should pass.
// Random clients should still be able to read and append entries.
#[tokio::test]
async fn public_permissions_with_app_restrictions() -> Result<(), AppError> {
    let app = create_app().await;
    let name: XorName = rand::random();
    let tag = 15_002;
    let data: Vec<AData> = vec![
        PubSeqAppendOnlyData::new(name, tag).into(),
        PubUnseqAppendOnlyData::new(name, tag).into(),
    ];
    for mut adata in data {
        let variant = adata.kind();
        let (mut app_key_tx, mut app_key_rx) = mpsc::channel(1);
        let (mut address_tx, mut address_rx) = mpsc::channel(1);
        let (mut remove_app_tx, mut remove_app_rx) = mpsc::channel(1);
        let (mut app_removed_tx, mut app_removed_rx) = mpsc::channel(1);

        let client = app.client.clone();
        let app_key = client.public_key().await;

        let local = LocalSet::new();
        let _ = local.spawn_local(async move {
            // Send the app's key to grant it access to the data
            app_key_tx
                .send(app_key)
                .await
                .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;
            // Wait for the address of the data on the network
            let address: ADataAddress = address_rx.recv().await.ok_or_else(|| {
                CoreError::Unexpected("failed to receive from channel".to_string())
            })?;
            let data = client.get_adata(address).await?;
            assert_eq!(*data.address(), address);
            let values = vec![ADataEntry::new(vec![3], vec![1, 2, 3])];
            if address.is_seq() {
                client
                    .append_seq_adata(
                        ADataAppendOperation { address, values },
                        data.entries_index(),
                    )
                    .await?;
            } else {
                client
                    .append_unseq_adata(ADataAppendOperation { address, values })
                    .await?;
            }

            let mut permissions = BTreeMap::new();
            let random_app = PublicKey::from(threshold_crypto::SecretKey::random().public_key());
            let _ = permissions.insert(
                ADataUser::Key(app_key),
                ADataPubPermissionSet::new(true, true),
            );
            let _ = permissions.insert(
                ADataUser::Key(random_app),
                ADataPubPermissionSet::new(true, true),
            );
            let _ = permissions.insert(ADataUser::Anyone, ADataPubPermissionSet::new(true, false));
            client
                .add_pub_adata_permissions(
                    address,
                    ADataPubPermissions {
                        permissions,
                        entries_index: 4,
                        owners_index: 1,
                    },
                    1,
                )
                .await?;
            random_app_access(address).await?;
            // Signal the client to remove the app from the data's permissions
            // and wait for the signal that the operation is complete
            remove_app_tx
                .send(())
                .await
                .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;
            app_removed_rx.recv().await.ok_or_else(|| {
                CoreError::Unexpected("failed to receive from channel".to_string())
            })?;
            let values = vec![ADataEntry::new(vec![6], vec![1, 2, 3])];
            let res = if address.is_seq() {
                client
                    .append_seq_adata(ADataAppendOperation { address, values }, 3)
                    .await
            } else {
                client
                    .append_unseq_adata(ADataAppendOperation { address, values })
                    .await
            };

            match res {
                Err(CoreError::DataError(SndError::AccessDenied)) => (),
                res => panic!("{:?}: Unexpected result: {:?}", variant, res),
            }
            let permissions = BTreeMap::new();
            match client
                .add_pub_adata_permissions(
                    address,
                    ADataPubPermissions {
                        permissions,
                        entries_index: 7,
                        owners_index: 1,
                    },
                    3,
                )
                .await
            {
                Err(CoreError::DataError(SndError::AccessDenied)) => (),
                res => panic!("{:?}: Unexpected result: {:?}", variant, res),
            }
            let data = client.get_adata(address).await?;
            assert_eq!(*data.address(), address);
            random_app_access(address).await?;

            Ok::<(), AppError>(())
        });

        let _ = local.spawn_local(async move {
            let client = random_client()?;

            // Wait for the app's key and add it to the data's permission list
            let app_pk: PublicKey = app_key_rx.recv().await.ok_or_else(|| {
                CoreError::Unexpected("failed to receive from channel".to_string())
            })?;

            let mut permissions = BTreeMap::new();
            let _ = permissions.insert(
                ADataUser::Key(app_pk),
                ADataPubPermissionSet::new(None, true),
            );
            let _ = permissions.insert(ADataUser::Anyone, ADataPubPermissionSet::new(true, None));

            adata.append_pub_permissions(
                ADataPubPermissions {
                    permissions,
                    entries_index: 0,
                    owners_index: 0,
                },
                0,
            )?;

            adata.append_owner(
                ADataOwner {
                    public_key: client.owner_key().await,
                    entries_index: 0,
                    permissions_index: 1,
                },
                0,
            )?;

            let entries = vec![
                ADataEntry::new(vec![0], vec![1, 2, 3]),
                ADataEntry::new(vec![1], vec![1, 2, 3]),
                ADataEntry::new(vec![2], vec![1, 2, 3]),
            ];
            let address = *adata.address();
            if address.is_seq() {
                adata.append_seq(entries, 0)?;
            } else {
                adata.append_unseq(entries)?;
            }
            client.put_adata(adata).await?;
            // Send the address of the data on the network
            address_tx
                .send(address)
                .await
                .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;
            // Wait for the signal to remove the app from the permissions list
            remove_app_rx.recv().await.ok_or_else(|| {
                CoreError::Unexpected("failed to receive from channel".to_string())
            })?;
            let mut permissions = BTreeMap::new();
            let _ = permissions.insert(
                ADataUser::Key(app_pk),
                ADataPubPermissionSet::new(false, false),
            );
            let _ = permissions.insert(ADataUser::Anyone, ADataPubPermissionSet::new(true, false));
            client
                .add_pub_adata_permissions(
                    address,
                    ADataPubPermissions {
                        permissions,
                        entries_index: 5,
                        owners_index: 1,
                    },
                    2,
                )
                .await?;
            // Signal that the app is removed from the permissions list
            app_removed_tx
                .send(())
                .await
                .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;

            Ok::<(), AppError>(())
        });

        local.await;
    }
    Ok(())
}

// Ensures that a random client has access to data at an address.
async fn random_app_access(address: ADataAddress) -> Result<(), AppError> {
    let app = create_app().await;
    let client = app.client;

    let data = client.get_adata(address).await?;
    assert_eq!(*data.address(), address);
    let key: [u8; 5] = rand::random();
    let values = vec![ADataEntry::new(key.to_vec(), vec![1, 2, 3])];
    if address.is_seq() {
        client
            .append_seq_adata(
                ADataAppendOperation { address, values },
                data.entries_index(),
            )
            .await?;
    } else {
        client
            .append_unseq_adata(ADataAppendOperation { address, values })
            .await?;
    }
    let index = data.entries_index() + 1;
    let entries = client
        .get_adata_range(address, (ADataIndex::FromStart(0), ADataIndex::FromEnd(0)))
        .await?;
    assert_eq!(entries.len() as u64, index);
    Ok(())
}
