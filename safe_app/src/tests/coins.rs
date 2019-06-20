// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Testing Safecoin operations from the apps point of view.

use crate::test_utils::{create_app, create_app_by_req, create_random_auth_req};
use crate::{run, AppError};
use futures::Future;
use routing::XorName;
use safe_core::{Client, CoreError};
use safe_nd::{response::Transaction, AppPermissions, Coins, Error, PublicKey};
use std::str::FromStr;

// Apps should not be able to request the coin balance if they don't have
// explicit permissions.
// 1. Create a user account with the default coin balance.
// 2. Create an app and authorise it _without_ giving a permissions to access the coin balance.
// 3. Try to get the coin balance from the app. This request must fail.
// 4. Try to transfer coins from balance A to some other random coin balance B. This request must fail.
// 5. Try to get an existing transaction from the app. This request must fail.
#[test]
fn coin_app_deny_permissions() {
    let app = create_app();

    unwrap!(run(&app, |client, _app_context| {
        let owner_bls_key = if let PublicKey::Bls(bls) = unwrap!(client.owner_key()) {
            bls
        } else {
            panic!("Unexpected key type")
        };
        let owner_coin_balance = XorName::from(unwrap!(client.owner_key()));
        client.create_coin_balance(
            &owner_coin_balance,
            unwrap!(Coins::from_str("100.0")),
            owner_bls_key,
        );

        let c2 = client.clone();
        let c3 = client.clone();

        client
            .get_balance(owner_coin_balance)
            .then(move |res| {
                match res {
                    Err(CoreError::NewRoutingClientError(Error::AccessDenied)) => (),
                    res => panic!("Unexpected result: {:?}", res),
                }

                c2.transfer_coins(
                    owner_coin_balance,
                    new_rand::random(),
                    unwrap!(Coins::from_str("1.0")),
                    None,
                )
            })
            .then(move |res| {
                match res {
                    Err(CoreError::NewRoutingClientError(Error::AccessDenied)) => (),
                    res => panic!("Unexpected result: {:?}", res),
                }

                c3.get_transaction(owner_coin_balance, 1)
            })
            .then(move |res| {
                match res {
                    Ok(Transaction::NoSuchTransaction) => (),
                    res => panic!("Unexpected result: {:?}", res),
                }
                Ok::<_, AppError>(())
            })
    }));
}

// 1. Create a user account with the default coin balance.
// 2. Create an app B and authorise it with a permission to access the coin balance.
// 3. GetBalance, TransferBalance, and GetTransaction requests should succeed.
#[test]
fn coin_app_allow_permissions() {
    // Create a recipient app
    let app = create_app();

    let coin_balance2 = unwrap!(run(&app, |client, _app_context| {
        let owner_bls_key = if let PublicKey::Bls(bls) = unwrap!(client.owner_key()) {
            bls
        } else {
            panic!("Unexpected key type")
        };
        let coin_balance2 = XorName::from(unwrap!(client.owner_key()));
        client.create_coin_balance(
            &coin_balance2,
            unwrap!(Coins::from_str("50.0")),
            owner_bls_key,
        );
        Ok(coin_balance2)
    }));

    // Create an app that can access the owner's coin balance.
    let mut app_auth_req = create_random_auth_req();
    app_auth_req.app_permissions = AppPermissions {
        transfer_coins: true,
    };

    let app = unwrap!(create_app_by_req(&app_auth_req));

    // Test the basic coin operations.
    unwrap!(run(&app, move |client, _app_context| {
        let owner_bls_key = if let PublicKey::Bls(bls) = unwrap!(client.owner_key()) {
            bls
        } else {
            panic!("Unexpected key type")
        };
        let owner_coin_balance = XorName::from(unwrap!(client.owner_key()));
        client.create_coin_balance(
            &owner_coin_balance,
            unwrap!(Coins::from_str("100.0")),
            owner_bls_key,
        );

        let c2 = client.clone();
        let c3 = client.clone();

        client
            .get_balance(owner_coin_balance)
            .then(move |res| {
                match res {
                    Ok(balance) => println!("{:?}", balance),
                    res => panic!("Unexpected result: {:?}", res),
                }

                c2.transfer_coins(
                    owner_coin_balance,
                    coin_balance2,
                    unwrap!(Coins::from_str("1.0")),
                    Some(1),
                )
            })
            .then(move |res| {
                match res {
                    Ok(_) => (),
                    res => panic!("Unexpected result: {:?}", res),
                }

                c3.get_transaction(owner_coin_balance, 1)
            })
            .then(move |res| {
                match res {
                    Ok(transaction) => println!("{:?}", transaction),
                    res => panic!("Unexpected result: {:?}", res),
                }
                Ok::<_, AppError>(())
            })
    }));
}
