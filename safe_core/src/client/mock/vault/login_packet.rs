// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Operation, Vault};
use crate::client::COST_OF_PUT;
use safe_nd::{Coins, Error as SndError, LoginPacketRequest, PublicKey, Response, Transaction};
use std::str::FromStr;
use unwrap::unwrap;

impl Vault {
    /// Process LoginPacket request
    pub(crate) fn process_login_packet_req(
        &mut self,
        request: &LoginPacketRequest,
        requester_pk: PublicKey,
        owner_pk: PublicKey,
    ) -> Response {
        match request {
            LoginPacketRequest::CreateFor {
                new_owner,
                amount,
                transaction_id,
                new_login_packet,
            } => {
                let source = owner_pk.into();
                let new_balance_dest = (*new_owner).into();

                // If a login packet at the given destination exists return an error.
                let result = if let Err(e) = {
                    // Check if the requester is authorized to perform coin transactions, mutate, and read balance.
                    let mut req_perms = vec![Operation::Mutation];
                    if *amount == unwrap!(Coins::from_str("0")) {
                        req_perms.push(Operation::TransferCoins);
                    }
                    self.authorise_operations(req_perms.as_slice(), source, requester_pk)
                } {
                    Err(e)
                } else {
                    self.get_balance(&source)
                        .and_then(|source_balance| {
                            let debit_amt = amount
                                .checked_add(COST_OF_PUT)
                                .ok_or(SndError::ExcessiveValue)?;
                            if !self.has_sufficient_balance(source_balance, debit_amt) {
                                return Err(SndError::InsufficientBalance);
                            }

                            // Create the balance and transfer the mentioned amount of coins
                            self.create_balance(new_balance_dest, *new_owner)
                        })
                        .and_then(|_| {
                            // Debit the requester's wallet the cost of `CreateLoginPacketFor`
                            self.commit_mutation(&source);
                            self.transfer_coins(source, new_balance_dest, *amount, *transaction_id)
                        })
                        .and_then(|_| {
                            if self
                                .get_login_packet(new_login_packet.destination())
                                .is_some()
                            {
                                Err(SndError::LoginPacketExists)
                            } else {
                                Ok(())
                            }
                        })
                        // Store the login packet
                        .map(|_| {
                            self.insert_login_packet(new_login_packet.clone());

                            Transaction {
                                id: *transaction_id,
                                amount: *amount,
                            }
                        })
                };
                Response::Transaction(result)
            }
            LoginPacketRequest::Create(account_data) => {
                let source = owner_pk.into();

                if let Err(e) =
                    self.authorise_operations(&[Operation::Mutation], source, requester_pk)
                {
                    Response::Mutation(Err(e))
                } else if self.get_login_packet(account_data.destination()).is_some() {
                    Response::Mutation(Err(SndError::LoginPacketExists))
                } else {
                    let result = self
                        .get_balance(&source)
                        .and_then(|source_balance| {
                            if !self.has_sufficient_balance(source_balance, COST_OF_PUT) {
                                return Err(SndError::InsufficientBalance);
                            }
                            self.commit_mutation(&source);
                            Ok(())
                        })
                        .map(|_| self.insert_login_packet(account_data.clone()));
                    Response::Mutation(result)
                }
            }
            LoginPacketRequest::Get(location) => {
                let result = match self.get_login_packet(&location) {
                    None => Err(SndError::NoSuchLoginPacket),
                    Some(login_packet) => {
                        if *login_packet.authorised_getter() == requester_pk {
                            Ok((
                                login_packet.data().to_vec(),
                                login_packet.signature().clone(),
                            ))
                        } else {
                            Err(SndError::AccessDenied)
                        }
                    }
                };
                Response::GetLoginPacket(result)
            }
            LoginPacketRequest::Update(new_packet) => {
                let result = {
                    match self.get_login_packet(new_packet.destination()) {
                        Some(old_packet) => {
                            if *old_packet.authorised_getter() == requester_pk {
                                self.insert_login_packet(new_packet.clone());
                                Ok(())
                            } else {
                                Err(SndError::AccessDenied)
                            }
                        }
                        None => Err(SndError::NoSuchLoginPacket),
                    }
                };
                Response::Mutation(result)
            }
        }
    }
}
