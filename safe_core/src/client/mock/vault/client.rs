// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Vault;
use safe_nd::{
    AppPermissions, ClientRequest, Error as SndError, PublicId, PublicKey, Response,
    Result as SndResult, XorName,
};
use std::collections::BTreeMap;
use unwrap::unwrap;

impl Vault {
    /// Process Client (Owner) request
    pub(crate) fn process_client_req(
        &mut self,
        request: &ClientRequest,
        requester: PublicId,
        requester_pk: PublicKey,
        owner_pk: PublicKey,
    ) -> Response {
        match request {
            ClientRequest::ListAuthKeysAndVersion => {
                let result = {
                    if owner_pk != requester_pk {
                        Err(SndError::AccessDenied)
                    } else {
                        Ok(self.list_auth_keys_and_version(&requester.name()))
                    }
                };
                Response::ListAuthKeysAndVersion(result)
            }
            ClientRequest::InsAuthKey {
                key,
                permissions,
                version,
            } => {
                let result = if owner_pk != requester_pk {
                    Err(SndError::AccessDenied)
                } else {
                    self.ins_auth_key(&requester.name(), *key, *permissions, *version)
                };
                Response::Mutation(result)
            }
            ClientRequest::DelAuthKey { key, version } => {
                let result = if owner_pk != requester_pk {
                    Err(SndError::AccessDenied)
                } else {
                    self.del_auth_key(&requester.name(), *key, *version)
                };
                Response::Mutation(result)
            }
        }
    }

    fn list_auth_keys_and_version(
        &mut self,
        name: &XorName,
    ) -> (BTreeMap<PublicKey, AppPermissions>, u64) {
        if self.get_client_manager_account(&name).is_none() {
            self.insert_account(*name);
        }
        let account = unwrap!(self.get_client_manager_account(&name));

        (account.auth_keys().clone(), account.version())
    }

    fn ins_auth_key(
        &mut self,
        name: &XorName,
        key: PublicKey,
        permissions: AppPermissions,
        version: u64,
    ) -> SndResult<()> {
        if self.get_client_manager_account(&name).is_none() {
            self.insert_account(*name);
        }
        let account = unwrap!(self.get_client_manager_account_mut(&name));

        account.ins_auth_key(key, permissions, version)
    }

    fn del_auth_key(&mut self, name: &XorName, key: PublicKey, version: u64) -> SndResult<()> {
        if self.get_client_manager_account(&name).is_none() {
            self.insert_account(*name);
        }
        let account = unwrap!(self.get_client_manager_account_mut(&name));

        account.del_auth_key(&key, version)
    }
}
