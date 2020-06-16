// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{DataId, Vault};
use safe_nd::{
    Data, Error as SndError, MData, MDataAction, MDataAddress, MDataKind, MDataRequest, PublicId,
    PublicKey, Response, Result as SndResult,
};

impl Vault {
    /// Process Mutable Data request
    pub(crate) fn process_mdata_req(
        &mut self,
        request: &MDataRequest,
        requester: PublicId,
        requester_pk: PublicKey,
        owner_pk: PublicKey,
    ) -> Response {
        match request {
            MDataRequest::Get(address) => {
                let result = self
                    .get_mdata(*address, requester_pk, &request)
                    .and_then(|data| {
                        if *address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        Ok(data)
                    });
                Response::GetMData(result)
            }
            MDataRequest::Put(data) => {
                let address = *data.address();

                let result = if data.owner() != owner_pk {
                    Err(SndError::InvalidOwners)
                } else {
                    self.put_data(
                        DataId::Mutable(address),
                        Data::Mutable(data.clone()),
                        requester,
                    )
                };
                Response::Mutation(result)
            }
            MDataRequest::GetValue { address, ref key } => {
                let data = self.get_mdata(*address, requester_pk, &request);

                match (address.kind(), data) {
                    (MDataKind::Seq, Ok(MData::Seq(mdata))) => {
                        let result = mdata
                            .get(&key)
                            .map(|value| value.clone().into())
                            .ok_or(SndError::NoSuchEntry);
                        Response::GetMDataValue(result)
                    }
                    (MDataKind::Unseq, Ok(MData::Unseq(mdata))) => {
                        let result = mdata
                            .get(&key)
                            .map(|value| value.clone().into())
                            .ok_or(SndError::NoSuchEntry);
                        Response::GetMDataValue(result)
                    }
                    (_, Err(err)) => Response::GetMDataValue(Err(err)),
                    (_, Ok(_)) => Response::GetMDataValue(Err(SndError::NoSuchData)),
                }
            }
            MDataRequest::GetShell(address) => {
                let result = self
                    .get_mdata(*address, requester_pk, &request)
                    .and_then(|data| {
                        if *address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        Ok(data.shell())
                    });
                Response::GetMDataShell(result)
            }
            MDataRequest::GetVersion(address) => {
                let result = self
                    .get_mdata(*address, requester_pk, &request)
                    .and_then(|data| {
                        if *address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        Ok(data.version())
                    });
                Response::GetMDataVersion(result)
            }
            MDataRequest::ListEntries(address) => {
                let data = self.get_mdata(*address, requester_pk, &request);

                match (address.kind(), data) {
                    (MDataKind::Seq, Ok(MData::Seq(mdata))) => {
                        Response::ListMDataEntries(Ok(mdata.entries().clone().into()))
                    }
                    (MDataKind::Unseq, Ok(MData::Unseq(mdata))) => {
                        Response::ListMDataEntries(Ok(mdata.entries().clone().into()))
                    }
                    (_, Err(err)) => Response::ListMDataEntries(Err(err)),
                    (_, Ok(_)) => Response::ListMDataEntries(Err(SndError::NoSuchData)),
                }
            }
            MDataRequest::ListKeys(address) => {
                let result = self
                    .get_mdata(*address, requester_pk, &request)
                    .and_then(|data| {
                        if *address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        Ok(data.keys())
                    });
                Response::ListMDataKeys(result)
            }
            MDataRequest::ListValues(address) => {
                let data = self.get_mdata(*address, requester_pk, &request);

                match (address.kind(), data) {
                    (MDataKind::Seq, Ok(MData::Seq(mdata))) => {
                        Response::ListMDataValues(Ok(mdata.values().into()))
                    }
                    (MDataKind::Unseq, Ok(MData::Unseq(mdata))) => {
                        Response::ListMDataValues(Ok(mdata.values().into()))
                    }
                    (_, Err(err)) => Response::ListMDataValues(Err(err)),
                    (_, Ok(_)) => Response::ListMDataValues(Err(SndError::NoSuchData)),
                }
            }
            MDataRequest::Delete(address) => {
                let result = self
                    .get_mdata(*address, requester_pk, &request)
                    .and_then(|data| {
                        if *address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        if let PublicId::Client(client_id) = requester.clone() {
                            if *client_id.public_key() == data.owner() {
                                self.delete_data(DataId::Mutable(*address));
                                Ok(())
                            } else {
                                Err(SndError::InvalidOwners)
                            }
                        } else {
                            Err(SndError::AccessDenied)
                        }
                    });
                Response::Mutation(result)
            }
            MDataRequest::SetUserPermissions {
                address,
                ref user,
                ref permissions,
                version,
            } => {
                let permissions = permissions.clone();
                let user = *user;

                let result =
                    self.get_mdata(*address, requester_pk, &request)
                        .and_then(|mut data| {
                            if *address != *data.address() {
                                return Err(SndError::NoSuchData);
                            }

                            let data_name = DataId::Mutable(*address);
                            data.set_user_permissions(user, permissions, *version)?;
                            self.insert_data(data_name, Data::Mutable(data));
                            self.debit_cost_of_mutation(&requester_pk);

                            Ok(())
                        });
                Response::Mutation(result)
            }
            MDataRequest::DelUserPermissions {
                address,
                ref user,
                version,
            } => {
                let user = *user;

                let result =
                    self.get_mdata(*address, requester_pk, &request)
                        .and_then(|mut data| {
                            if *address != *data.address() {
                                return Err(SndError::NoSuchData);
                            }

                            let data_name = DataId::Mutable(*address);
                            data.del_user_permissions(user, *version)?;
                            self.insert_data(data_name, Data::Mutable(data));
                            self.debit_cost_of_mutation(&requester_pk);

                            Ok(())
                        });
                Response::Mutation(result)
            }
            MDataRequest::ListUserPermissions { address, ref user } => {
                let user = *user;

                let result = self
                    .get_mdata(*address, requester_pk, &request)
                    .and_then(|data| {
                        if *address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        data.user_permissions(user).map(|perm| perm.clone())
                    });
                Response::ListMDataUserPermissions(result)
            }
            MDataRequest::ListPermissions(address) => {
                let result = self
                    .get_mdata(*address, requester_pk, &request)
                    .and_then(|data| {
                        if *address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        Ok(data.permissions())
                    });
                Response::ListMDataPermissions(result)
            }
            MDataRequest::MutateEntries {
                address,
                ref actions,
            } => {
                let result =
                    self.get_mdata(*address, requester_pk, &request)
                        .and_then(move |mut data| {
                            if *address != *data.address() {
                                return Err(SndError::NoSuchData);
                            }

                            let data_name = DataId::Mutable(*address);
                            data.mutate_entries(actions.clone(), requester_pk)?;
                            self.insert_data(data_name, Data::Mutable(data));
                            self.debit_cost_of_mutation(&requester_pk);

                            Ok(())
                        });
                Response::Mutation(result)
            }
        }
    }

    pub fn get_mdata(
        &mut self,
        address: MDataAddress,
        requester_pk: PublicKey,
        request: &MDataRequest,
    ) -> SndResult<MData> {
        match self.get_data(&DataId::Mutable(address)) {
            Some(data_type) => match data_type {
                Data::Mutable(data) => {
                    check_perms_mdata(&data, request, requester_pk).map(move |_| data)
                }
                _ => Err(SndError::NoSuchData),
            },
            None => Err(SndError::NoSuchData),
        }
    }
}

fn check_perms_mdata(data: &MData, request: &MDataRequest, requester: PublicKey) -> SndResult<()> {
    match request {
        MDataRequest::Get { .. }
        | MDataRequest::GetShell { .. }
        | MDataRequest::GetVersion { .. }
        | MDataRequest::ListKeys { .. }
        | MDataRequest::ListEntries { .. }
        | MDataRequest::ListValues { .. }
        | MDataRequest::GetValue { .. }
        | MDataRequest::ListPermissions { .. }
        | MDataRequest::ListUserPermissions { .. } => {
            data.check_permissions(MDataAction::Read, requester)
        }

        MDataRequest::SetUserPermissions { .. } | MDataRequest::DelUserPermissions { .. } => {
            data.check_permissions(MDataAction::ManagePermissions, requester)
        }

        MDataRequest::MutateEntries { .. } => Ok(()),

        MDataRequest::Delete { .. } => data.check_is_owner(requester),

        MDataRequest::Put { .. } => Err(SndError::InvalidOperation),
    }
}
