// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{AuthError, AuthFuture};
use crate::access_container;
use crate::app_auth::{app_state, AppState};
use crate::client::AuthClient;
use crate::config;
use ffi_utils::StringError;
use futures::future::{self, Either};
use futures::Future;
use maidsafe_utilities::serialisation::deserialise;
use routing::{ClientError, User, XorName};
use rust_sodium::crypto::sign;
use safe_core::ffi::ipc::resp::MetadataResponse as FfiUserMetadata;
use safe_core::ipc::req::{
    container_perms_into_permission_set, ContainerPermissions, IpcReq, ShareMDataReq,
};
use safe_core::ipc::resp::{AccessContainerEntry, IpcResp, UserMetadata, METADATA_KEY};
use safe_core::ipc::{self, IpcError, IpcMsg};
use safe_core::{recovery, Client, CoreError, FutureExt};
use std::collections::HashMap;
use std::ffi::CString;

/// Decodes a given encoded IPC message and returns either an `IpcMsg` struct or
/// an error code + description & an encoded `IpcMsg::Resp` in case of an error
#[cfg_attr(feature = "cargo-clippy", allow(type_complexity))]
pub fn decode_ipc_msg(
    client: &AuthClient,
    msg: IpcMsg,
) -> Box<AuthFuture<Result<IpcMsg, (i32, CString, CString)>>> {
    match msg {
        IpcMsg::Req {
            req: IpcReq::Auth(auth_req),
            req_id,
        } => {
            // Ok status should be returned for all app states (including
            // Revoked and Authenticated).
            ok!(Ok(IpcMsg::Req {
                req_id,
                req: IpcReq::Auth(auth_req),
            }))
        }
        IpcMsg::Req {
            req: IpcReq::Unregistered(extra_data),
            req_id,
        } => ok!(Ok(IpcMsg::Req {
            req_id,
            req: IpcReq::Unregistered(extra_data),
        })),
        IpcMsg::Req {
            req: IpcReq::ShareMData(share_mdata_req),
            req_id,
        } => ok!(Ok(IpcMsg::Req {
            req_id,
            req: IpcReq::ShareMData(share_mdata_req),
        })),
        IpcMsg::Req {
            req: IpcReq::Containers(cont_req),
            req_id,
        } => {
            let app_id = cont_req.app.id.clone();

            let c2 = client.clone();

            config::list_apps(client)
                .and_then(move |(_config_version, config)| app_state(&c2, &config, &app_id))
                .and_then(move |app_state| {
                    match app_state {
                        AppState::Authenticated => Ok(Ok(IpcMsg::Req {
                            req_id,
                            req: IpcReq::Containers(cont_req),
                        })),
                        AppState::Revoked | AppState::NotAuthenticated => {
                            // App is not authenticated
                            let (error_code, description) =
                                ffi_error!(AuthError::from(IpcError::UnknownApp));

                            let resp = IpcMsg::Resp {
                                resp: IpcResp::Auth(Err(IpcError::UnknownApp)),
                                req_id,
                            };
                            let resp = encode_response(&resp)?;

                            Ok(Err((error_code, description, resp)))
                        }
                    }
                }).into_box()
        }
        IpcMsg::Resp { .. } | IpcMsg::Revoked { .. } | IpcMsg::Err(..) => {
            return err!(AuthError::IpcError(IpcError::InvalidMsg));
        }
    }
}

/// Updates containers permissions (adds a given key to the permissions set)
pub fn update_container_perms(
    client: &AuthClient,
    permissions: HashMap<String, ContainerPermissions>,
    sign_pk: sign::PublicKey,
) -> Box<AuthFuture<AccessContainerEntry>> {
    let c2 = client.clone();

    access_container::fetch_authenticator_entry(client)
        .and_then(move |(_, mut root_containers)| {
            let mut reqs = Vec::new();
            let client = c2.clone();

            for (container_key, access) in permissions {
                let c2 = client.clone();
                let mdata_info = fry!(
                    root_containers
                        .remove(&container_key)
                        .ok_or_else(|| AuthError::NoSuchContainer(container_key.clone()))
                );
                let perm_set = container_perms_into_permission_set(&access);

                let fut = client
                    .get_mdata_version(mdata_info.name, mdata_info.type_tag)
                    .and_then(move |version| {
                        recovery::set_mdata_user_permissions(
                            &c2,
                            mdata_info.name,
                            mdata_info.type_tag,
                            User::Key(sign_pk),
                            perm_set,
                            version + 1,
                        ).map(move |_| (container_key, mdata_info, access))
                    }).map_err(AuthError::from);

                reqs.push(fut);
            }

            future::join_all(reqs).into_box()
        }).map(|perms| {
            perms
                .into_iter()
                .map(|(container_key, dir, access)| (container_key, (dir, access)))
                .collect()
        }).map_err(AuthError::from)
        .into_box()
}

pub fn encode_response(msg: &IpcMsg) -> Result<CString, IpcError> {
    let resp = ipc::encode_msg(msg)?;
    Ok(CString::new(resp).map_err(StringError::from)?)
}

enum ShareMDataError {
    InvalidOwner(XorName, u64),
    InvalidMetadata,
}

pub fn decode_share_mdata_req(
    client: &AuthClient,
    req: &ShareMDataReq,
) -> Box<AuthFuture<Vec<Option<FfiUserMetadata>>>> {
    let user = fry!(
        client
            .public_signing_key()
            .ok_or_else(|| AuthError::Unexpected("Public signing key not found".to_string()))
    );
    let num_mdata = req.mdata.len();
    let mut futures = Vec::with_capacity(num_mdata);

    for mdata in &req.mdata {
        let client = client.clone();
        let name = mdata.name;
        let type_tag = mdata.type_tag;

        let future = client
            .get_mdata_shell(name, type_tag)
            .and_then(move |shell| {
                if shell.owners().contains(&user) {
                    let future_metadata = client
                        .get_mdata_value(name, type_tag, METADATA_KEY.into())
                        .then(move |res| match res {
                            Ok(value) => Ok(deserialise::<UserMetadata>(&value.content)
                                .map_err(|_| ShareMDataError::InvalidMetadata)
                                .and_then(move |metadata| {
                                    match metadata.into_md_response(name, type_tag) {
                                        Ok(meta) => Ok(meta),
                                        Err(_) => Err(ShareMDataError::InvalidMetadata),
                                    }
                                })),
                            Err(CoreError::RoutingClientError(ClientError::NoSuchEntry)) => {
                                // Allow requesting shared access to arbitrary Mutable Data objects even
                                // if they don't have metadata.
                                let user_metadata = UserMetadata {
                                    name: None,
                                    description: None,
                                };
                                let user_md_response = user_metadata
                                    .into_md_response(name, type_tag)
                                    .map_err(|_| ShareMDataError::InvalidMetadata);
                                Ok(user_md_response)
                            }
                            Err(error) => Err(error),
                        });
                    Either::A(future_metadata)
                } else {
                    Either::B(future::ok(Err(ShareMDataError::InvalidOwner(
                        name, type_tag,
                    ))))
                }
            }).map_err(AuthError::from);

        futures.push(future);
    }

    future::join_all(futures)
        .and_then(move |results| {
            let mut metadata_cont = Vec::with_capacity(num_mdata);
            let mut invalids = Vec::with_capacity(num_mdata);

            for result in results {
                match result {
                    Ok(metadata) => metadata_cont.push(Some(metadata)),
                    Err(ShareMDataError::InvalidMetadata) => metadata_cont.push(None),
                    Err(ShareMDataError::InvalidOwner(name, type_tag)) => {
                        invalids.push((name, type_tag))
                    }
                }
            }

            if invalids.is_empty() {
                Ok(metadata_cont)
            } else {
                Err(AuthError::IpcError(IpcError::InvalidOwner(invalids)))
            }
        }).into_box()
}
