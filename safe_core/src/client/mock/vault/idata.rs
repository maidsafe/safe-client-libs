// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{DataId, Vault};
use safe_nd::{
    Data, Error as SndError, IData, IDataAddress, IDataRequest, PublicId, PublicKey, Response,
    Result as SndResult,
};

impl Vault {
    /// Process Immutable Data request
    pub(crate) fn process_idata_req(
        &mut self,
        request: &IDataRequest,
        requester: PublicId,
        requester_pk: PublicKey,
        owner_pk: PublicKey,
    ) -> Response {
        match request {
            IDataRequest::Get(address) => {
                let result = self.get_idata(*address).and_then(|idata| match idata {
                    IData::Unpub(ref data) => {
                        // Check permissions for unpub idata.
                        if *data.owner() == requester_pk {
                            Ok(idata)
                        } else {
                            Err(SndError::AccessDenied)
                        }
                    }
                    IData::Pub(_) => Ok(idata),
                });
                Response::GetIData(result)
            }
            IDataRequest::Put(idata) => {
                let mut errored = false;
                if let IData::Unpub(data) = idata.clone() {
                    if owner_pk != *data.owner() {
                        errored = true
                    }
                }

                let result = if errored {
                    Err(SndError::InvalidOwners)
                } else {
                    println!(
                        "HEre in putting idata.... we try as requester...., {:?}",
                        requester
                    );
                    self.put_data(
                        DataId::Immutable(*idata.address()),
                        Data::Immutable(idata.clone()),
                        requester,
                    )
                };

                println!("result as we have it: {:?}", result);
                Response::Mutation(result)
            }
            IDataRequest::DeleteUnpub(address) => {
                let result = self.delete_idata(*address, requester_pk);
                Response::Mutation(result)
            }
        }
    }

    pub fn get_idata(&mut self, address: IDataAddress) -> SndResult<IData> {
        let data_name = DataId::Immutable(address);

        match self.get_data(&data_name) {
            Some(data_type) => match data_type {
                Data::Immutable(data) => Ok(data),
                _ => Err(SndError::NoSuchData),
            },
            None => Err(SndError::NoSuchData),
        }
    }

    pub fn delete_idata(
        &mut self,
        address: IDataAddress,
        requester_pk: PublicKey,
    ) -> SndResult<()> {
        let data_id = DataId::Immutable(address);

        match self.get_data(&data_id) {
            Some(idata) => {
                if let Data::Immutable(data) = idata {
                    if let IData::Unpub(unpub_idata) = data {
                        if *unpub_idata.owner() == requester_pk {
                            self.delete_data(data_id);
                            Ok(())
                        } else {
                            Err(SndError::AccessDenied)
                        }
                    } else {
                        Err(SndError::InvalidOperation)
                    }
                } else {
                    Err(SndError::NoSuchData)
                }
            }
            None => Err(SndError::NoSuchData),
        }
    }
}
