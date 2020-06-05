// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Testing Safecoin operations from the apps point of view.

use crate::test_utils::{create_app, create_app_by_req, create_random_auth_req};
use crate::AppError;
use safe_core::{Client, CoreError};
use safe_nd::{AppPermissions, Error, Money, XorName};
use std::str::FromStr;

// Apps should not be able to request the coin balance if they don't have
// explicit permissions.
// 1. Create a user account with the default coin balance.
// 2. Create an app and authorise it _without_ giving a permissions to access the coin balance.
// 3. Try to get the coin balance from the app. This request must fail.
// 4. Try to transfer coins from balance A to some other random coin balance B. This request must fail.
// 5. Try to get an existing transfer_id from the app. This request must fail.
#[tokio::test]
async fn coin_app_deny_permissions() -> Result<(), AppError> {
    let mut app_auth_req = create_random_auth_req();
    app_auth_req.app_permissions = AppPermissions {
        transfer_money: false,
        data_mutations: false,
        read_balance: false,
    };

    let app = create_app_by_req(&app_auth_req).await?;

    let client = app.client;

    match client.get_balance(None).await {
        Err(CoreError::DataError(Error::AccessDenied)) => (),
        res => panic!("Unexpected result: {:?}", res),
    }

    match client
        .transfer_money(None, rand::random(), Money::from_str("1.0")?, None)
        .await
    {
        Err(CoreError::DataError(Error::AccessDenied)) => (),
        res => panic!("Unexpected result: {:?}", res),
    }
    Ok(())
}

// 1. Create a user account with the default coin balance.
// 2. Create an app B and authorise it with a permission to access the coin balance.
// 3. GetBalance, TransferBalance, and GetTransfer requests should succeed.
#[tokio::test]
async fn coin_app_allow_permissions() -> Result<(), AppError> {
    // Create a recipient app
    let app = create_app().await;
    let client = app.client;
    let coin_balance = XorName::from(client.owner_key().await);

    // Create an app that can access and transfer coins from the owner's coin balance.
    let mut app_auth_req = create_random_auth_req();
    app_auth_req.app_permissions = AppPermissions {
        transfer_money: true,
        data_mutations: false,
        read_balance: true,
    };

    let _app = create_app_by_req(&app_auth_req).await?;

    // Test the basic coin operations.
    let _ = client.get_balance(None).await?;

    match client
        .transfer_money(None, coin_balance, Money::from_str("1.0")?, Some(1))
        .await
    {
        Ok(transfer_id) => {
            assert_eq!(transfer_id.id, 1);
            assert_eq!(transfer_id.amount, Money::from_str("1.0")?);
        }
        res => panic!("Unexpected result: {:?}", res),
    }
    Ok(())
}
