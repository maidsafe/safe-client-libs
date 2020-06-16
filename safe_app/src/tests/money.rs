// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Testing Safemoney operations from the apps point of view.

use crate::test_utils::{create_app, create_app_by_req, create_random_auth_req};
use crate::AppError;
use safe_core::{Client, CoreError};
use safe_nd::{AppPermissions, Error, Money, ClientFullId};
use std::str::FromStr;
use rand::thread_rng;

// Apps should not be able to request the money balance if they don't have
// explicit permissions.
// 1. Create a user account with the default money balance.
// 2. Create an app and authorise it _without_ giving a permissions to access the money balance.
// 3. Try to get the money balance from the app. This request must fail.
// 4. Try to transfer money from balance A to some other random money balance B. This request must fail.
// 5. Try to get an existing transfer_id from the app. This request must fail.
#[tokio::test]
async fn money_app_deny_permissions()  {
    let mut app_auth_req = create_random_auth_req();
    app_auth_req.app_permissions = AppPermissions {
        transfer_money: false,
        data_mutations: false,
        read_balance: false,
        read_transfer_history: false,

    };


    // need to know how this creates its client. 
    let app = create_app_by_req(&app_auth_req).await.unwrap();

    let client = app.client;

    // what client was this trying to get prior??
    // if its just the appp client...
    // how should our mock auth operations behave?

    // This app client should not have money....const
    /// this app client should be trying to query
    match client.get_balance(None).await {
        Err(CoreError::DataError(Error::AccessDenied)) => (),
        res => panic!("Unexpected result: {:?}", res),
    }

    // let seed = rand::random();
    let mut rng = thread_rng();
    let random_target_pk = *ClientFullId::new_bls(&mut rng).public_id().public_key();

    println!(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>..");
    println!(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>..");
    println!(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>..");
    println!(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>..");
    println!(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>..");
    println!(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>..");
    match client
        .transfer_money( random_target_pk, Money::from_str("1.0").unwrap())
        .await
    {
        Err(CoreError::DataError(Error::AccessDenied)) => (),
        res => panic!("Unexpected result: {:?}", res),
    }
}

// 1. Create a user account with the default money balance.
// 2. Create an app B and authorise it with a permission to access the money balance.
// 3. GetBalance, TransferBalance, and GetTransfer requests should succeed.
#[tokio::test]
async fn money_app_allow_permissions() {
    // Create a recipient app
    let app = create_app().await;
    let client = app.client;
    let money_balance = client.owner_key().await;

    // Create an app that can access and transfer money from the owner's money balance.
    let mut app_auth_req = create_random_auth_req();
    app_auth_req.app_permissions = AppPermissions {
        transfer_money: true,
        data_mutations: false,
        read_balance: true,
        read_transfer_history: true,

    };

    let _app = create_app_by_req(&app_auth_req).await.unwrap();

    // Test the basic money operations.
    let _ = client.get_balance(None).await.unwrap();

    match client
        .transfer_money( money_balance, Money::from_str("1.1").unwrap())
        .await
    {
        Ok(transfer) => {
            assert_eq!(transfer.amount(), Money::from_str("1.1").unwrap());
        }
        res => panic!("Unexpected result: {:?}", res),
    }
}
