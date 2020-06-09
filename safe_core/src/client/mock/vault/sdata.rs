// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{DataId, Vault};
use safe_nd::{
    Data, Error as SndError, PublicId, PublicKey, Response, Result as SndResult, SData,
    SDataAction, SDataAddress, SDataIndex, SDataRequest,
};

impl Vault {
    /// Process Sequence Data request
    pub(crate) fn process_sdata_req(
        &mut self,
        request: &SDataRequest,
        requester: PublicId,
        requester_pk: PublicKey,
        owner_pk: PublicKey,
    ) -> Response {
        match request {
            SDataRequest::Store(sdata) => {
                let owner_index = sdata.owners_index();
                let address = *sdata.address();

                let result = match sdata.owner(owner_index - 1) {
                    Some(key) => {
                        if key.public_key != owner_pk {
                            Err(SndError::InvalidOwners)
                        } else {
                            self.put_data(
                                DataId::Sequence(address),
                                Data::Sequence(sdata.clone()),
                                requester,
                            )
                        }
                    }
                    None => Err(SndError::NoSuchEntry),
                };
                Response::Mutation(result)
            }
            SDataRequest::Get(address) => {
                let result = self.get_sdata(*address, requester_pk, &request);
                Response::GetSData(result)
            }
            SDataRequest::Delete(address) => {
                let id = DataId::Sequence(*address);
                let result = self.get_sdata(*address, requester_pk, &request).and_then(
                    move |data| match data {
                        // Cannot be deleted as it is a published data.
                        SData::Public(_) => Err(SndError::InvalidOperation),
                        SData::Private(_) => {
                            self.delete_data(id);
                            Ok(())
                        }
                    },
                );
                Response::Mutation(result)
            }
            SDataRequest::GetRange { address, range } => {
                let result =
                    self.get_sdata(*address, requester_pk, &request)
                        .and_then(move |data| {
                            data.in_range(range.0, range.1).ok_or(SndError::NoSuchEntry)
                        });
                Response::GetSDataRange(result)
            }
            SDataRequest::GetLastEntry(address) => {
                let result =
                    self.get_sdata(*address, requester_pk, &request)
                        .and_then(move |data| {
                            let entry = data.last_entry().cloned().ok_or(SndError::NoSuchEntry)?;
                            Ok((data.entries_index() - 1, entry))
                        });
                Response::GetSDataLastEntry(result)
            }
            SDataRequest::GetPermissions {
                address,
                permissions_index,
            } => {
                let data = self.get_sdata(*address, requester_pk, &request);

                match (address.kind(), data) {
                    (kind, Ok(ref data)) if kind.is_pub() && data.is_pub() => {
                        Response::GetSDataPermissions(
                            data.pub_permissions(*permissions_index)
                                .map(|perm| perm.clone().into()),
                        )
                    }
                    (kind, Ok(ref data)) if kind.is_priv() && data.is_priv() => {
                        Response::GetSDataPermissions(
                            data.priv_permissions(*permissions_index)
                                .map(|perm| perm.clone().into()),
                        )
                    }
                    (_, Err(err)) => Response::GetSDataPermissions(Err(err)),
                    (_, Ok(_)) => Response::GetSDataPermissions(Err(SndError::NoSuchData)),
                }
            }
            SDataRequest::GetUserPermissions {
                address,
                permissions_index,
                user,
            } => {
                let result = self
                    .get_sdata(*address, requester_pk, &request)
                    .and_then(move |data| data.user_permissions(*user, *permissions_index));
                Response::GetSDataUserPermissions(result)
            }
            SDataRequest::Mutate(op) => {
                let id = DataId::Sequence(op.address);
                let result = self.get_sdata(op.address, requester_pk, &request).and_then(
                    move |mut sdata| {
                        sdata.apply_crdt_op(op.crdt_op.clone());
                        self.commit_mutation(requester.name());
                        self.insert_data(id, Data::Sequence(sdata));
                        Ok(())
                    },
                );
                Response::Mutation(result)
            }
            SDataRequest::SetPermissions {
                address,
                permissions,
            } => {
                let id = DataId::Sequence(*address);
                let result =
                    self.get_sdata(*address, requester_pk, &request)
                        .and_then(move |mut sdata| {
                            sdata.set_permissions(&permissions)?;
                            self.commit_mutation(requester.name());
                            self.insert_data(id, Data::Sequence(sdata));
                            Ok(())
                        });
                Response::Mutation(result)
            }
            SDataRequest::SetOwner { address, owner } => {
                let id = DataId::Sequence(*address);
                let result =
                    self.get_sdata(*address, requester_pk, &request)
                        .and_then(move |mut sdata| {
                            sdata.set_owner(*owner);
                            self.commit_mutation(requester.name());
                            self.insert_data(id, Data::Sequence(sdata));
                            Ok(())
                        });
                Response::Mutation(result)
            }
            SDataRequest::GetOwner {
                address,
                owners_index,
            } => {
                let result =
                    self.get_sdata(*address, requester_pk, &request)
                        .and_then(move |sdata| {
                            let index = match owners_index {
                                SDataIndex::FromStart(index) => *index,
                                SDataIndex::FromEnd(index) => (sdata.owners_index() - index),
                            };
                            match sdata.owner(index) {
                                Some(owner) => Ok(*owner),
                                None => Err(SndError::NoSuchEntry),
                            }
                        });
                Response::GetSDataOwner(result)
            }
        }
    }

    pub fn get_sdata(
        &mut self,
        address: SDataAddress,
        requester_pk: PublicKey,
        request: &SDataRequest,
    ) -> SndResult<SData> {
        let data_id = DataId::Sequence(address);
        match self.get_data(&data_id) {
            Some(Data::Sequence(sdata)) => {
                check_perms_sdata(&sdata, request, requester_pk).map(move |_| sdata)
            }
            Some(_) | None => Err(SndError::NoSuchData),
        }
    }
}

fn check_perms_sdata(sdata: &SData, request: &SDataRequest, requester: PublicKey) -> SndResult<()> {
    match request {
        SDataRequest::Get(..)
        | SDataRequest::GetRange { .. }
        | SDataRequest::GetLastEntry(..)
        | SDataRequest::GetPermissions { .. }
        | SDataRequest::GetUserPermissions { .. }
        | SDataRequest::GetOwner { .. } => match sdata {
            SData::Public(_) => Ok(()),
            SData::Private(_) => sdata.check_permission(SDataAction::Read, requester),
        },
        SDataRequest::Mutate { .. } => sdata.check_permission(SDataAction::Append, requester),
        SDataRequest::SetPermissions { .. } => {
            sdata.check_permission(SDataAction::ManagePermissions, requester)
        }
        SDataRequest::SetOwner { .. } => sdata.check_is_last_owner(requester),
        SDataRequest::Delete(_) => match sdata {
            SData::Public(_) => Err(SndError::InvalidOperation),
            SData::Private(_) => sdata.check_is_last_owner(requester),
        },
        SDataRequest::Store { .. } => Err(SndError::InvalidOperation),
    }
}
