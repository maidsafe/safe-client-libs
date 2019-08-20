// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::client::AuthClient;
use crate::errors::AuthError;
use crate::ipc::decode_ipc_msg;
use crate::{access_container, app_auth, config, revocation, run, Authenticator};
use env_logger::{fmt::Formatter, Builder as LoggerBuilder};
use ffi_utils::test_utils::{send_via_user_data, sender_as_user_data};
use ffi_utils::{vec_clone_from_raw_parts, FfiResult, ReprC};
use futures::{future, Future, IntoFuture};
use log::Record;
use rand::{self, Rng};
use routing::XorName;
use safe_core::client::{test_create_balance, Client};
use safe_core::crypto::shared_secretbox;
use safe_core::ffi::ipc::req::{
    AuthReq as FfiAuthReq, ContainersReq as FfiContainersReq, ShareMDataReq as FfiShareMDataReq,
};
use safe_core::ffi::ipc::resp::MetadataResponse as FfiUserMetadata;
use safe_core::ipc::req::{container_perms_into_permission_set, ContainerPermissions};
use safe_core::ipc::resp::AccessContainerEntry;
use safe_core::ipc::resp::UserMetadata;
use safe_core::ipc::{
    self, AppExchangeInfo, AuthGranted, AuthReq, ContainersReq, IpcMsg, IpcReq, ShareMDataReq,
};
use safe_core::nfs::file_helper::{self, Version};
use safe_core::nfs::{File, Mode};
use safe_core::utils::test_utils::setup_client_with_net_obs;
#[cfg(feature = "mock-network")]
use safe_core::ConnectionManager;
use safe_core::{utils, MDataInfo, NetworkEvent};
use safe_nd::{AppPermissions, Coins, PublicKey};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fmt::Debug;
use std::io::Write;
use std::os::raw::{c_char, c_void};
use std::slice;
use std::str::FromStr;
use std::sync::mpsc;
use std::time::Duration;

/// Assert that expression `$e` matches the pattern `$p`.
#[macro_export]
macro_rules! assert_match {
    ($e:expr, $p:pat) => {
        match $e {
            $p => (),
            x => panic!("Unexpected {:?} (expecting {})", x, stringify!($p)),
        }
    };
}

#[derive(Debug)]
/// Payload.
pub enum Payload {
    /// Metadata.
    Metadata(Vec<(Option<UserMetadata>, XorName, u64)>),
}

/// Channel type.
pub type ChannelType = Result<(IpcMsg, Option<Payload>), (i32, Option<IpcMsg>)>;

/// Initialise `env_logger` with custom settings.
pub fn init_log() {
    let do_format = move |formatter: &mut Formatter, record: &Record<'_>| {
        let now = formatter.timestamp();
        writeln!(
            formatter,
            "{} {} [{}:{}] {}",
            formatter.default_styled_level(record.level()),
            now,
            record.file().unwrap_or_default(),
            record.line().unwrap_or_default(),
            record.args()
        )
    };
    let _ = LoggerBuilder::from_default_env()
        .format(do_format)
        .is_test(true)
        .try_init();
}

/// Creates a new random account for authenticator. Returns the `Authenticator`
/// instance and the locator and password strings.
pub fn create_authenticator() -> (Authenticator, String, String) {
    let mut rng = rand::thread_rng();

    let locator: String = rng.gen_ascii_chars().take(10).collect();
    let password: String = rng.gen_ascii_chars().take(10).collect();
    let balance_sk = threshold_crypto::SecretKey::random();
    unwrap!(test_create_balance(
        &balance_sk,
        unwrap!(Coins::from_str("100"))
    ));

    let auth = unwrap!(Authenticator::create_acc(
        locator.clone(),
        password.clone(),
        balance_sk,
        || (),
    ));

    (auth, locator, password)
}

/// Create a random authenticator and login using the same credentials.
pub fn create_account_and_login() -> Authenticator {
    let (_, locator, password) = create_authenticator();

    trace!("Created an account with random login and password, logging in");
    unwrap!(Authenticator::login(locator, password, || ()))
}

/// Revoke an app, returning an error on failure
pub fn try_revoke(authenticator: &Authenticator, app_id: &str) -> Result<(), AuthError> {
    let app_id = app_id.to_string();

    run(authenticator, move |client| {
        revocation::revoke_app(client, &app_id)
    })
}

/// Revoke an app, panicking on failure
pub fn revoke(authenticator: &Authenticator, app_id: &str) {
    match try_revoke(authenticator, app_id) {
        Ok(_) => (),
        x => panic!("Unexpected {:?}", x),
    }
}

/// Create a random authenticator and login using the same credentials.
/// Attaches a hook to the Routing to override responses.
#[cfg(all(any(test, feature = "testing"), feature = "mock-network"))]
pub fn create_account_and_login_with_hook<F>(hook: F) -> Authenticator
where
    F: Fn(ConnectionManager) -> ConnectionManager + Send + 'static,
{
    let (_, locator, password) = create_authenticator();
    unwrap!(Authenticator::login_with_hook(
        locator,
        password,
        || (),
        hook,
    ))
}

/// Returns `AppInfo` iff the app is listed in the authenticator config.
pub fn get_app_or_err(
    authenticator: &Authenticator,
    app_id: &str,
) -> Result<config::AppInfo, AuthError> {
    let app_id = app_id.to_string();

    run(authenticator, move |client| {
        config::get_app(client, &app_id)
    })
}

/// Registers a mock application using a given `AuthReq`.
pub fn register_app(
    authenticator: &Authenticator,
    auth_req: &AuthReq,
) -> Result<AuthGranted, AuthError> {
    let req_id = ipc::gen_req_id();
    let msg = IpcMsg::Req {
        req_id,
        req: IpcReq::Auth(auth_req.clone()),
    };

    // Invoke `decode_ipc_msg` and expect to get AuthReq back.
    let ipc_req = unwrap!(run(authenticator, move |client| decode_ipc_msg(
        client, msg
    )));
    match ipc_req {
        Ok(IpcMsg::Req {
            req: IpcReq::Auth(_),
            ..
        }) => (),
        x => return Err(AuthError::Unexpected(format!("Unexpected {:?}", x))),
    }

    let auth_req = auth_req.clone();
    run(authenticator, move |client| {
        trace!("Authenticating app: {:?}", auth_req);
        app_auth::authenticate(client, auth_req)
    })
}

/// Register a random app. Returns the ID of the app and the `AuthGranted` struct.
#[allow(clippy::implicit_hasher)]
pub fn register_rand_app(
    authenticator: &Authenticator,
    app_container: bool,
    containers_req: HashMap<String, ContainerPermissions>,
) -> Result<(String, AuthGranted), AuthError> {
    let auth_req = AuthReq {
        app: rand_app(),
        app_container,
        app_permissions: AppPermissions {
            transfer_coins: true,
        },
        containers: containers_req,
    };

    let auth_granted = register_app(authenticator, &auth_req)?;
    let app_id = auth_req.app.id;

    Ok((app_id, auth_granted))
}

/// Creates a random `AppExchangeInfo`
pub fn rand_app() -> AppExchangeInfo {
    let mut rng = rand::thread_rng();

    AppExchangeInfo {
        id: rng.gen_ascii_chars().take(10).collect(),
        scope: None,
        name: rng.gen_ascii_chars().take(10).collect(),
        vendor: rng.gen_ascii_chars().take(10).collect(),
    }
}

/// Create file in the given container, with the given name and content.
pub fn create_file<S: Into<String>>(
    authenticator: &Authenticator,
    container_info: MDataInfo,
    name: S,
    content: Vec<u8>,
    published: bool,
) -> Result<(), AuthError> {
    let name = name.into();
    run(authenticator, move |client| {
        let c2 = client.clone();

        file_helper::write(
            client.clone(),
            File::new(vec![], published),
            Mode::Overwrite,
            container_info.enc_key().cloned(),
        )
        .then(move |res| {
            let writer = unwrap!(res);
            writer.write(&content).and_then(move |_| writer.close())
        })
        .then(move |file| file_helper::insert(c2, container_info, name, &unwrap!(file)))
        .map_err(From::from)
    })
}

/// Fetches file from the given directory by given name.
pub fn fetch_file<S: Into<String>>(
    authenticator: &Authenticator,
    container_info: MDataInfo,
    name: S,
) -> Result<File, AuthError> {
    let name = name.into();

    run(authenticator, |client| {
        file_helper::fetch(client.clone(), container_info, name)
            .map(|(_, file)| file)
            .map_err(From::from)
    })
}

/// Reads from the given file.
pub fn read_file(
    authenticator: &Authenticator,
    file: File,
    encryption_key: Option<shared_secretbox::Key>,
) -> Result<Vec<u8>, AuthError> {
    run(authenticator, move |client| {
        file_helper::read(client.clone(), &file, encryption_key)
            .then(|res| {
                let reader = unwrap!(res);
                reader.read(0, reader.size())
            })
            .map_err(From::from)
    })
}

/// Deletes file from the given directory by given name.
pub fn delete_file<S: Into<String>>(
    authenticator: &Authenticator,
    container_info: MDataInfo,
    name: S,
    published: bool,
    version: u64,
) -> Result<u64, AuthError> {
    let name = name.into();

    run(authenticator, move |client| {
        file_helper::delete(
            client.clone(),
            container_info,
            name,
            published,
            Version::Custom(version),
        )
        .map_err(From::from)
    })
}

/// Writes to the given file.
pub fn write_file(
    authenticator: &Authenticator,
    file: File,
    mode: Mode,
    encryption_key: Option<shared_secretbox::Key>,
    content: Vec<u8>,
) -> Result<(), AuthError> {
    run(authenticator, move |client| {
        file_helper::write(client.clone(), file, mode, encryption_key)
            .then(move |res| {
                let writer = unwrap!(res);
                writer
                    .write(&content)
                    .and_then(move |_| writer.close().map(|_| ()))
            })
            .map_err(From::from)
    })
}

/// Fetch the access container entry for the app.
pub fn access_container<S: Into<String>>(
    authenticator: &Authenticator,
    app_id: S,
    auth_granted: AuthGranted,
) -> AccessContainerEntry {
    unwrap!(
        try_access_container(authenticator, app_id, auth_granted),
        "Access container entry is empty"
    )
}

/// Fetch the access container entry for the app.
pub fn try_access_container<S: Into<String>>(
    authenticator: &Authenticator,
    app_id: S,
    auth_granted: AuthGranted,
) -> Option<AccessContainerEntry> {
    let app_keys = auth_granted.app_keys;
    let app_id = app_id.into();
    unwrap!(run(authenticator, move |client| {
        access_container::fetch_entry(client, &app_id, app_keys).map(move |(_, entry)| entry)
    }))
}

/// Get the container `MDataInfo` from the authenticator entry in the access container.
pub fn get_container_from_authenticator_entry(
    authenticator: &Authenticator,
    container: &str,
) -> Result<MDataInfo, AuthError> {
    let container = String::from(container);

    run(authenticator, move |client| {
        access_container::fetch_authenticator_entry(client).and_then(move |(_, mut ac_entries)| {
            ac_entries.remove(&container).ok_or_else(|| {
                AuthError::from(format!("'{}' not found in the access container", container))
            })
        })
    })
}

/// Check that the given permission set is contained in the access container
#[allow(clippy::implicit_hasher)]
pub fn compare_access_container_entries(
    authenticator: &Authenticator,
    app_pk: PublicKey,
    mut access_container: AccessContainerEntry,
    expected: HashMap<String, ContainerPermissions>,
) {
    let results = unwrap!(run(authenticator, move |client| {
        let mut reqs = Vec::new();
        let user = app_pk;

        for (container, expected_perms) in expected {
            // Check the requested permissions in the access container.
            let expected_perm_set = container_perms_into_permission_set(&expected_perms);
            let (md_info, perms) = unwrap!(
                access_container.remove(&container),
                "No '{}' in access container {:?}",
                container,
                access_container
            );
            assert_eq!(perms, expected_perms);

            let fut = client
                .list_mdata_user_permissions(*md_info.address(), user)
                .map(move |perms| (perms, expected_perm_set));

            reqs.push(fut);
        }

        future::join_all(reqs).map_err(AuthError::from)
    }));

    // Check the permission on the mutable data for each of the above directories.
    for (perms, expected) in results {
        assert_eq!(perms, expected);
    }
}

/// Create random registered client and run it inside an event loop. Use this to
/// create an `AuthClient` automatically and randomly.
pub fn random_client<Run, I, T, E>(r: Run) -> T
where
    Run: FnOnce(&AuthClient) -> I + Send + 'static,
    I: IntoFuture<Item = T, Error = E> + 'static,
    T: Send + 'static,
    E: Debug,
{
    let n = |net_event| panic!("Unexpected NetworkEvent occurred: {:?}", net_event);
    random_client_with_net_obs(n, r)
}

/// Create random registered client and run it inside an event loop. Use this to
/// create an `AuthClient` automatically and randomly.
pub fn random_client_with_net_obs<NetObs, Run, I, T, E>(n: NetObs, r: Run) -> T
where
    NetObs: FnMut(NetworkEvent) + 'static,
    Run: FnOnce(&AuthClient) -> I + Send + 'static,
    I: IntoFuture<Item = T, Error = E> + 'static,
    T: Send + 'static,
    E: Debug,
{
    let c = |el_h, core_tx, net_tx| {
        let acc_locator = unwrap!(utils::generate_random_string(10));
        let acc_password = unwrap!(utils::generate_random_string(10));
        let balance_sk = threshold_crypto::SecretKey::random();
        unwrap!(test_create_balance(
            &balance_sk,
            unwrap!(Coins::from_str("10"))
        ));
        AuthClient::registered(
            &acc_locator,
            &acc_password,
            balance_sk,
            el_h,
            core_tx,
            net_tx,
        )
    };
    setup_client_with_net_obs(&(), c, n, r)
}

// TODO: There should be a public function with a signature like this, and the
//       FFI function `ipc::decode_ipc_msg` should be only wrapper over it.
/// Helper to decode IpcMsg.
pub fn auth_decode_ipc_msg_helper(authenticator: &Authenticator, msg: &str) -> ChannelType {
    let (tx, rx) = mpsc::channel::<ChannelType>();

    extern "C" fn auth_cb(user_data: *mut c_void, req_id: u32, req: *const FfiAuthReq) {
        unsafe {
            let req = match AuthReq::clone_from_repr_c(req) {
                Ok(req) => req,
                Err(_) => return send_via_user_data::<ChannelType>(user_data, Err((-2, None))),
            };

            let msg = IpcMsg::Req {
                req_id,
                req: IpcReq::Auth(req),
            };

            send_via_user_data::<ChannelType>(user_data, Ok((msg, None)))
        }
    }

    extern "C" fn containers_cb(user_data: *mut c_void, req_id: u32, req: *const FfiContainersReq) {
        unsafe {
            let req = match ContainersReq::clone_from_repr_c(req) {
                Ok(req) => req,
                Err(_) => return send_via_user_data::<ChannelType>(user_data, Err((-2, None))),
            };

            let msg = IpcMsg::Req {
                req_id,
                req: IpcReq::Containers(req),
            };

            send_via_user_data::<ChannelType>(user_data, Ok((msg, None)))
        }
    }

    extern "C" fn share_mdata_cb(
        user_data: *mut c_void,
        req_id: u32,
        req: *const FfiShareMDataReq,
        ffi_metadata: *const FfiUserMetadata,
        ffi_metadata_len: usize,
    ) {
        unsafe {
            let req = match ShareMDataReq::clone_from_repr_c(req) {
                Ok(req) => req,
                Err(_) => return send_via_user_data::<ChannelType>(user_data, Err((-2, None))),
            };

            let metadatas: Vec<_> = slice::from_raw_parts(ffi_metadata, ffi_metadata_len)
                .iter()
                .map(|ffi_metadata| {
                    (
                        if ffi_metadata.name.is_null() {
                            None
                        } else {
                            Some(unwrap!(UserMetadata::clone_from_repr_c(ffi_metadata)))
                        },
                        XorName(ffi_metadata.xor_name),
                        ffi_metadata.type_tag,
                    )
                })
                .collect();

            let msg = IpcMsg::Req {
                req_id,
                req: IpcReq::ShareMData(req),
            };

            send_via_user_data::<ChannelType>(
                user_data,
                Ok((msg, Some(Payload::Metadata(metadatas)))),
            )
        }
    }

    let ffi_msg = unwrap!(CString::new(msg));
    let mut ud = Default::default();

    unsafe {
        crate::ffi::ipc::auth_decode_ipc_msg(
            authenticator,
            ffi_msg.as_ptr(),
            sender_as_user_data(&tx, &mut ud),
            auth_cb,
            containers_cb,
            unregistered_cb,
            share_mdata_cb,
            err_cb,
        );
    };

    let ret = match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(r) => r,
        Err(e) => {
            error!("auth_decode_ipc_msg_helper: {:?}", e);
            Err((-1, None))
        }
    };
    drop(tx);
    ret
}

/// Unregistered callback.
pub extern "C" fn unregistered_cb(
    user_data: *mut c_void,
    req_id: u32,
    extra_data: *const u8,
    extra_data_len: usize,
) {
    unsafe {
        let msg = IpcMsg::Req {
            req_id,
            req: IpcReq::Unregistered(vec_clone_from_raw_parts(extra_data, extra_data_len)),
        };

        send_via_user_data::<ChannelType>(user_data, Ok((msg, None)))
    }
}

/// Error callback.
pub extern "C" fn err_cb(user_data: *mut c_void, res: *const FfiResult, response: *const c_char) {
    unsafe {
        let ipc_resp = if response.is_null() {
            None
        } else {
            let response = CStr::from_ptr(response);
            match ipc::decode_msg(unwrap!(response.to_str())) {
                Ok(ipc_resp) => Some(ipc_resp),
                Err(_) => None,
            }
        };

        send_via_user_data::<ChannelType>(user_data, Err(((*res).error_code, ipc_resp)))
    }
}
