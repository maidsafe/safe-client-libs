// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Operation, Vault};
use crate::client::COST_OF_PUT;
use rand::Rng;
use safe_nd::{
    ClientFullId, DebitAgreementProof, Error as SndError, Money, SignedTransfer, MoneyRequest, PublicKey, Response,
    SafeKey, Transfer, TransferRegistered, XorName,
};
use std::str::FromStr;
use threshold_crypto::SecretKeySet;
use unwrap::unwrap;

impl Vault {
    /// Process Money request
    pub(crate) fn process_money_req(
        &mut self,
        request: &MoneyRequest,
        requester_pk: PublicKey,
        owner_pk: PublicKey,
    ) -> Response {
        // let mut rng = rand::Rng::thread_rng();
        let mut rng = rand::thread_rng();
        let client_safe_key = SafeKey::client(ClientFullId::new_ed25519(&mut rng));
        let fake_signature = client_safe_key.sign(b"mock-key");

        match request {
            #[cfg(feature="simulated-payouts")]
            MoneyRequest::SimulatePayout { transfer } => {
                // let source = owner_pk;
                let destination = transfer.to();
                let amount = transfer.amount();
                let transfer_id = transfer.id();
                // let bls_secret_key_set = SecretKeySet::random(1, &mut rng);
                // let elder_pk_set = bls_secret_key_set.public_keys();

                let result = if transfer.amount().as_nano() == 0 {
                    // TODO do we have other invalid states in SafeTransfer
                    Err(SndError::InvalidOperation)
                } else {
                    // self.authorise_operations(&[Operation::TransferMoney], source, requester_pk)
                    //     .and_then(|()| {
                    self.farming_payout( destination, amount, transfer_id )
                        // })
                };

                // as we're mock, we'll just reply with a registered Transfer and negate the validation steps
                let final_result = match result {
                    Ok(_) => {
                        Ok(TransferRegistered {
                            debit_proof: DebitAgreementProof {
                                signed_transfer: SignedTransfer {
                                    transfer:transfer.clone(), 
                                    actor_signature: fake_signature.clone()
                                },
                                debiting_replicas_sig: fake_signature,
                            },
                        })

                    },
                    Err(e) => Err(e)
                };

                Response::TransferRegistration(final_result)
            }
            MoneyRequest::ValidateTransfer { signed_transfer } => {
                let source = owner_pk.into();
                let destination = signed_transfer.to();
                let amount = signed_transfer.amount();
                let transfer_id = signed_transfer.id();
                let bls_secret_key_set = SecretKeySet::random(1, &mut rng);
                let elder_pk_set = bls_secret_key_set.public_keys();


                let result = if signed_transfer.amount().as_nano() == 0 {
                    // TODO do we have other invalid states in SafeTransfer
                    Err(SndError::InvalidOperation)
                } else {
                    self.authorise_operations(&[Operation::TransferMoney], source, requester_pk)
                        .and_then(|()| {
                            self.transfer_money(source, amount, destination, transfer_id)
                        })
                };

                // as we're mock, we'll just reply with a registered Transfer and negate the validation steps
                let final_result = match result {
                    Ok(_) => {
                        Ok(TransferRegistered {
                            debit_proof: DebitAgreementProof {
                                signed_transfer: signed_transfer.clone(),
                                debiting_replicas_sig: fake_signature,
                            },
                        })

                    },
                    Err(e) => Err(e)
                };

                Response::TransferRegistration(final_result)
            }
            MoneyRequest::RegisterTransfer { .. } => {
                Response::TransferRegistration(Err(SndError::from("Register Transfer Unimplemented for mock")))

                // TODO
            }
            MoneyRequest::PropagateTransfer { .. } => {
                panic!("SCL Mock vault should not receive this request.");
                Response::TransferRegistration(Err(SndError::from("PropagateTransfer Unimplemented for mock")))
            }
            MoneyRequest::GetHistory { .. } => {
                let source = owner_pk.into();

                let result = self.authorise_operations(&[Operation::GetHistory], source, requester_pk)
                .and_then(|()| {
                    // self.get_history(source, amount, destination, transfer_id)
                    
                    // Return generic history for now...
                    Ok(vec![])
                });
                
                Response::GetHistory(result)
                // do this
            }
            // MoneyRequest::CreateBalance {
            //     amount,
            //     new_balance_owner,
            //     transfer_id,
            // } => {
            //     let source = owner_pk.into();
            //     let destination = (*new_balance_owner).into();

            //     let result = if source == destination {
            //         self.mock_create_balance(*new_balance_owner, *amount);
            //         Ok(Transfer {
            //             id: *transfer_id,
            //             amount: *amount,
            //         })
            //     } else {
            //         let mut req_perms = vec![Operation::Mutation];
            //         if *amount == unwrap!(Money::from_str("0")) {
            //             req_perms.push(Operation::TransferMoney);
            //         }
            //         self.authorise_operations(req_perms.as_slice(), source, requester_pk)
            //             .and_then(|_| self.get_balance(&source))
            //             .and_then(|source_balance| {
            //                 let total_amount = amount
            //                     .checked_add(COST_OF_PUT)
            //                     .ok_or(SndError::ExcessiveValue)?;
            //                 if !self.has_sufficient_balance(source_balance, total_amount) {
            //                     return Err(SndError::InsufficientBalance);
            //                 }
            //                 self.create_balance(destination, *new_balance_owner)
            //             })
            //             .and_then(|()| {
            //                 self.commit_mutation(&source);
            //                 self.transfer_money(source, destination, *amount, *transfer_id)
            //             })
            //     };
            //     Response::TransferRegistration(result)
            // }
            MoneyRequest::GetBalance(public_key) => {
                let result = self
                    .authorise_operations(&[Operation::GetBalance], *public_key, requester_pk)
                    .and_then(move |_| self.get_balance(&public_key));
                Response::GetBalance(result)
            }
        }
    }
}
