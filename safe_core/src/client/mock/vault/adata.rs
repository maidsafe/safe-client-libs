// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{DataId, Vault};
use safe_nd::{
    AData, ADataAction, ADataAddress, ADataIndex, ADataRequest, AppendOnlyData, Data,
    Error as SndError, PublicId, PublicKey, Response, Result as SndResult, SeqAppendOnly,
    UnseqAppendOnly,
};

impl Vault {
    /// Process AppendOnly Data request
    pub(crate) fn process_adata_req(
        &mut self,
        request: &ADataRequest,
        requester: PublicId,
        requester_pk: PublicKey,
        owner_pk: PublicKey,
    ) -> Response {
        match request {
            ADataRequest::Put(adata) => {
                let owner_index = adata.owners_index();
                let address = *adata.address();

                let result = match adata.owner(owner_index - 1) {
                    Some(key) => {
                        if key.public_key != owner_pk {
                            Err(SndError::InvalidOwners)
                        } else {
                            self.put_data(
                                DataId::AppendOnly(address),
                                Data::AppendOnly(adata.clone()),
                                requester,
                            )
                        }
                    }
                    None => Err(SndError::NoSuchEntry),
                };
                Response::Mutation(result)
            }
            ADataRequest::Get(address) => {
                let result = self.get_adata(*address, requester_pk, &request);
                Response::GetAData(result)
            }
            ADataRequest::Delete(address) => {
                let id = DataId::AppendOnly(*address);
                let result = self.get_adata(*address, requester_pk, &request).and_then(
                    move |data| match data {
                        // Cannot be deleted as it is a published data.
                        AData::PubSeq(_) | AData::PubUnseq(_) => Err(SndError::InvalidOperation),
                        AData::UnpubSeq(_) | AData::UnpubUnseq(_) => {
                            self.delete_data(id);
                            Ok(())
                        }
                    },
                );
                Response::Mutation(result)
            }
            ADataRequest::GetShell {
                address,
                data_index,
            } => {
                let result =
                    self.get_adata(*address, requester_pk, &request)
                        .and_then(move |data| {
                            let index = match data_index {
                                ADataIndex::FromStart(index) => *index,
                                ADataIndex::FromEnd(index) => (data.permissions_index() - index),
                            };
                            data.shell(index)
                        });
                Response::GetADataShell(result)
            }
            ADataRequest::GetRange { address, range } => {
                let result =
                    self.get_adata(*address, requester_pk, &request)
                        .and_then(move |data| {
                            data.in_range(range.0, range.1).ok_or(SndError::NoSuchEntry)
                        });
                Response::GetADataRange(result)
            }
            ADataRequest::GetValue { address, ref key } => {
                let result = self
                    .get_adata(*address, requester_pk, &request)
                    .and_then(move |data| data.get(key).cloned().ok_or(SndError::NoSuchEntry));
                Response::GetADataValue(result)
            }
            ADataRequest::GetIndices(address) => {
                let result = self
                    .get_adata(*address, requester_pk, &request)
                    .and_then(move |data| data.indices());
                Response::GetADataIndices(result)
            }
            ADataRequest::GetLastEntry(address) => {
                let result = self
                    .get_adata(*address, requester_pk, &request)
                    .and_then(move |data| data.last_entry().cloned().ok_or(SndError::NoSuchEntry));
                Response::GetADataLastEntry(result)
            }
            ADataRequest::GetPermissions {
                address,
                permissions_index,
            } => {
                let data = self.get_adata(*address, requester_pk, &request);

                match (address.kind(), data) {
                    (kind, Ok(ref data)) if kind.is_pub() && data.is_pub() => {
                        Response::GetADataPermissions(
                            data.pub_permissions(*permissions_index)
                                .map(|perm| perm.clone().into()),
                        )
                    }
                    (kind, Ok(ref data)) if kind.is_unpub() && data.is_unpub() => {
                        Response::GetADataPermissions(
                            data.unpub_permissions(*permissions_index)
                                .map(|perm| perm.clone().into()),
                        )
                    }
                    (_, Err(err)) => Response::GetADataPermissions(Err(err)),
                    (_, Ok(_)) => Response::GetADataPermissions(Err(SndError::NoSuchData)),
                }
            }
            ADataRequest::GetPubUserPermissions {
                address,
                permissions_index,
                user,
            } => {
                let result = self
                    .get_adata(*address, requester_pk, &request)
                    .and_then(move |data| data.pub_user_permissions(*user, *permissions_index));
                Response::GetPubADataUserPermissions(result)
            }
            ADataRequest::GetUnpubUserPermissions {
                address,
                permissions_index,
                public_key,
            } => {
                let result =
                    self.get_adata(*address, requester_pk, &request)
                        .and_then(move |data| {
                            data.unpub_user_permissions(*public_key, *permissions_index)
                        });
                Response::GetUnpubADataUserPermissions(result)
            }
            ADataRequest::AppendSeq { append, index } => {
                let id = DataId::AppendOnly(append.address);
                let result = self
                    .get_adata(append.address, requester_pk, &request)
                    .and_then(move |data| match data {
                        AData::PubSeq(mut adata) => {
                            adata.append(append.values.clone(), *index)?;
                            self.commit_mutation(&requester.public_key());
                            self.insert_data(id, Data::AppendOnly(AData::PubSeq(adata)));
                            Ok(())
                        }
                        AData::UnpubSeq(mut adata) => {
                            adata.append(append.values.clone(), *index)?;
                            self.commit_mutation(&requester.public_key());
                            self.insert_data(id, Data::AppendOnly(AData::UnpubSeq(adata)));
                            Ok(())
                        }
                        _ => Err(SndError::NoSuchData),
                    });
                Response::Mutation(result)
            }
            ADataRequest::AppendUnseq(append) => {
                let id = DataId::AppendOnly(append.address);
                let result = self
                    .get_adata(append.address, requester_pk, &request)
                    .and_then(move |data| match data {
                        AData::PubUnseq(mut adata) => {
                            adata.append(append.values.clone())?;
                            self.commit_mutation(&requester.public_key());
                            self.insert_data(id, Data::AppendOnly(AData::PubUnseq(adata)));
                            Ok(())
                        }
                        AData::UnpubUnseq(mut adata) => {
                            adata.append(append.values.clone())?;
                            self.commit_mutation(&requester.public_key());
                            self.insert_data(id, Data::AppendOnly(AData::UnpubUnseq(adata)));
                            Ok(())
                        }
                        _ => Err(SndError::NoSuchData),
                    });
                Response::Mutation(result)
            }
            ADataRequest::AddPubPermissions {
                address,
                permissions,
                permissions_index,
            } => {
                let id = DataId::AppendOnly(*address);
                let result =
                    self.get_adata(*address, requester_pk, &request)
                        .and_then(move |data| match address {
                            ADataAddress::PubSeq { .. } => match data {
                                AData::PubSeq(mut adata) => {
                                    adata.append_permissions(
                                        permissions.clone(),
                                        *permissions_index,
                                    )?;
                                    self.commit_mutation(&requester.public_key());
                                    self.insert_data(id, Data::AppendOnly(AData::PubSeq(adata)));
                                    Ok(())
                                }
                                _ => Err(SndError::NoSuchData),
                            },
                            ADataAddress::PubUnseq { .. } => match data {
                                AData::PubUnseq(mut adata) => {
                                    adata.append_permissions(
                                        permissions.clone(),
                                        *permissions_index,
                                    )?;
                                    self.commit_mutation(&requester.public_key());
                                    self.insert_data(id, Data::AppendOnly(AData::PubUnseq(adata)));
                                    Ok(())
                                }
                                _ => Err(SndError::NoSuchData),
                            },
                            _ => Err(SndError::AccessDenied),
                        });
                Response::Mutation(result)
            }
            ADataRequest::AddUnpubPermissions {
                address,
                permissions,
                permissions_index,
            } => {
                let id = DataId::AppendOnly(*address);
                let result = self
                    .get_adata(*address, requester_pk, &request)
                    .and_then(|data| match address {
                        ADataAddress::UnpubSeq { .. } => match data.clone() {
                            AData::UnpubSeq(mut adata) => {
                                adata
                                    .append_permissions(permissions.clone(), *permissions_index)?;
                                self.commit_mutation(&requester.public_key());
                                self.insert_data(id, Data::AppendOnly(AData::UnpubSeq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        ADataAddress::UnpubUnseq { .. } => match data {
                            AData::UnpubUnseq(mut adata) => {
                                adata
                                    .append_permissions(permissions.clone(), *permissions_index)?;
                                self.commit_mutation(&requester.public_key());
                                self.insert_data(id, Data::AppendOnly(AData::UnpubUnseq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        _ => Err(SndError::AccessDenied),
                    });
                Response::Mutation(result)
            }
            ADataRequest::SetOwner {
                address,
                owner,
                owners_index,
            } => {
                let id = DataId::AppendOnly(*address);
                let result =
                    self.get_adata(*address, requester_pk, &request)
                        .and_then(move |data| match address {
                            ADataAddress::PubSeq { .. } => match data {
                                AData::PubSeq(mut adata) => {
                                    adata.append_owner(*owner, *owners_index)?;
                                    self.commit_mutation(&requester.public_key());
                                    self.insert_data(id, Data::AppendOnly(AData::PubSeq(adata)));
                                    Ok(())
                                }
                                _ => Err(SndError::NoSuchData),
                            },
                            ADataAddress::PubUnseq { .. } => match data {
                                AData::PubUnseq(mut adata) => {
                                    adata.append_owner(*owner, *owners_index)?;
                                    self.commit_mutation(&requester.public_key());
                                    self.insert_data(id, Data::AppendOnly(AData::PubUnseq(adata)));
                                    Ok(())
                                }
                                _ => Err(SndError::NoSuchData),
                            },
                            ADataAddress::UnpubSeq { .. } => match data.clone() {
                                AData::UnpubSeq(mut adata) => {
                                    adata.append_owner(*owner, *owners_index)?;
                                    self.commit_mutation(&requester.public_key());
                                    self.insert_data(id, Data::AppendOnly(AData::UnpubSeq(adata)));
                                    Ok(())
                                }
                                _ => Err(SndError::NoSuchData),
                            },
                            ADataAddress::UnpubUnseq { .. } => match data {
                                AData::UnpubUnseq(mut adata) => {
                                    adata.append_owner(*owner, *owners_index)?;
                                    self.commit_mutation(&requester.public_key());
                                    self.insert_data(
                                        id,
                                        Data::AppendOnly(AData::UnpubUnseq(adata)),
                                    );
                                    Ok(())
                                }
                                _ => Err(SndError::NoSuchData),
                            },
                        });
                Response::Mutation(result)
            }
            ADataRequest::GetOwners {
                address,
                owners_index,
            } => {
                let result =
                    self.get_adata(*address, requester_pk, &request)
                        .and_then(move |data| {
                            let index = match owners_index {
                                ADataIndex::FromStart(index) => *index,
                                ADataIndex::FromEnd(index) => (data.owners_index() - index),
                            };
                            match data.owner(index) {
                                Some(owner) => Ok(*owner),
                                None => Err(SndError::NoSuchEntry),
                            }
                        });
                Response::GetADataOwners(result)
            }
        }
    }

    pub fn get_adata(
        &mut self,
        address: ADataAddress,
        requester_pk: PublicKey,
        request: &ADataRequest,
    ) -> SndResult<AData> {
        let data_id = DataId::AppendOnly(address);
        match self.get_data(&data_id) {
            Some(data_type) => match data_type {
                Data::AppendOnly(data) => {
                    check_perms_adata(&data, request, requester_pk).map(move |_| data)
                }
                _ => Err(SndError::NoSuchData),
            },
            None => Err(SndError::NoSuchData),
        }
    }
}

fn check_perms_adata(data: &AData, request: &ADataRequest, requester: PublicKey) -> SndResult<()> {
    match request {
        ADataRequest::Get(..)
        | ADataRequest::GetShell { .. }
        | ADataRequest::GetValue { .. }
        | ADataRequest::GetRange { .. }
        | ADataRequest::GetIndices(..)
        | ADataRequest::GetLastEntry(..)
        | ADataRequest::GetPermissions { .. }
        | ADataRequest::GetPubUserPermissions { .. }
        | ADataRequest::GetUnpubUserPermissions { .. }
        | ADataRequest::GetOwners { .. } => match data {
            AData::PubUnseq(_) | AData::PubSeq(_) => Ok(()),
            AData::UnpubSeq(_) | AData::UnpubUnseq(_) => {
                data.check_permission(ADataAction::Read, requester)
            }
        },
        ADataRequest::AppendSeq { .. } | ADataRequest::AppendUnseq { .. } => {
            data.check_permission(ADataAction::Append, requester)
        }
        ADataRequest::AddPubPermissions { .. } | ADataRequest::AddUnpubPermissions { .. } => {
            data.check_permission(ADataAction::ManagePermissions, requester)
        }
        ADataRequest::SetOwner { .. } => data.check_is_last_owner(requester),
        ADataRequest::Delete(_) => match data {
            AData::PubSeq(_) | AData::PubUnseq(_) => Err(SndError::InvalidOperation),
            AData::UnpubSeq(_) | AData::UnpubUnseq(_) => data.check_is_last_owner(requester),
        },
        ADataRequest::Put { .. } => Err(SndError::InvalidOperation),
    }
}
