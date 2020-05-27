// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Operation, Vault};
use crate::client::COST_OF_PUT;
use safe_nd::{Coins, CoinsRequest, Error as SndError, PublicKey, Response, Transaction, XorName};
use std::str::FromStr;
use unwrap::unwrap;

impl Vault {
    /// Process Coins request
    pub(crate) fn process_coins_req(
        &mut self,
        request: &CoinsRequest,
        requester_pk: PublicKey,
        owner_pk: PublicKey,
    ) -> Response {
        match request {
            CoinsRequest::Transfer {
                destination,
                amount,
                transaction_id,
            } => {
                let source: XorName = owner_pk.into();

                let result = if amount.as_nano() == 0 {
                    Err(SndError::InvalidOperation)
                } else {
                    self.authorise_operations(&[Operation::TransferCoins], source, requester_pk)
                        .and_then(|()| {
                            self.transfer_coins(source, *destination, *amount, *transaction_id)
                        })
                };
                Response::Transaction(result)
            }
            CoinsRequest::CreateBalance {
                amount,
                new_balance_owner,
                transaction_id,
            } => {
                let source = owner_pk.into();
                let destination = (*new_balance_owner).into();

                let result = if source == destination {
                    self.mock_create_balance(*new_balance_owner, *amount);
                    Ok(Transaction {
                        id: *transaction_id,
                        amount: *amount,
                    })
                } else {
                    let mut req_perms = vec![Operation::Mutation];
                    if *amount == unwrap!(Coins::from_str("0")) {
                        req_perms.push(Operation::TransferCoins);
                    }
                    self.authorise_operations(req_perms.as_slice(), source, requester_pk)
                        .and_then(|_| self.get_balance(&source))
                        .and_then(|source_balance| {
                            let total_amount = amount
                                .checked_add(COST_OF_PUT)
                                .ok_or(SndError::ExcessiveValue)?;
                            if !self.has_sufficient_balance(source_balance, total_amount) {
                                return Err(SndError::InsufficientBalance);
                            }
                            self.create_balance(destination, *new_balance_owner)
                        })
                        .and_then(|()| {
                            self.commit_mutation(&source);
                            self.transfer_coins(source, destination, *amount, *transaction_id)
                        })
                };
                Response::Transaction(result)
            }
            CoinsRequest::GetBalance => {
                let coin_balance_id = owner_pk.into();

                let result = self
                    .authorise_operations(&[Operation::GetBalance], coin_balance_id, requester_pk)
                    .and_then(move |_| self.get_balance(&coin_balance_id));
                Response::GetBalance(result)
            }
        }
    }
}
