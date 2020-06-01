// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Provides utilities to test the authenticator functionality.

#![allow(clippy::not_unsafe_ptr_arg_deref, unsafe_code)]

use crate::client::AuthClient;
use crate::errors::AuthError;
use crate::ipc::decode_ipc_msg;
use crate::{access_container, app_auth, config, revocation, Authenticator};
use env_logger::{fmt::Formatter, Builder as LoggerBuilder};
use futures::Future;

use log::trace;
use log::Record;
use safe_core::client::{test_create_balance, Client};
use safe_core::core_structs::AccessContainerEntry;
use safe_core::core_structs::UserMetadata;
use safe_core::crypto::shared_secretbox;
use safe_core::ipc::req::{container_perms_into_permission_set, ContainerPermissions};
use safe_core::ipc::{self, AppExchangeInfo, AuthGranted, AuthReq, IpcMsg, IpcReq};
use safe_core::nfs::file_helper::{self, Version};
use safe_core::nfs::{File, Mode};
use safe_core::utils::test_utils::{gen_client_id, setup_client_with_net_obs};
#[cfg(feature = "mock-network")]
use safe_core::ConnectionManager;
use safe_core::{utils, MDataInfo, NetworkEvent};
use safe_nd::{AppPermissions, Money, PublicKey, XorName};
#[cfg(feature = "mock-network")]
use safe_nd::{Error as SndError, MDataRequest, Request, Response};
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::Write;
use std::str::FromStr;
use unwrap::unwrap;

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

/// Payload.
#[derive(Debug)]
pub enum Payload {
    /// Metadata.
    Metadata(Vec<(Option<UserMetadata>, XorName, u64)>),
}

/// Channel type.
pub type ChannelType = Result<(IpcMsg, Option<Payload>), (i32, Option<IpcMsg>)>;

/// Initialises `env_logger` with custom settings.
pub fn init_log() {
    let do_format = move |formatter: &mut Formatter, record: &Record| {
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
pub async fn create_authenticator() -> (Authenticator, String, String) {
    let locator: String = unwrap!(utils::generate_readable_string(10));
    let password: String = unwrap!(utils::generate_readable_string(10));
    let client_id = gen_client_id();

    let coins = unwrap!(Money::from_str("100"));
    let _ = test_create_balance(&client_id, coins).await;

    let auth = unwrap!(
        Authenticator::create_client_with_acc(locator.clone(), password.clone(), client_id, || (),)
            .await
    );

    (auth, locator, password)
}

/// Amount of seed subparts used when calculating values from a seed.
pub const SEED_SUBPARTS: usize = 4;

/// Divide `seed` into the number of subparts given by `SEED_SUBPARTS`.
pub fn divide_seed(seed: &str) -> Result<[&[u8]; SEED_SUBPARTS], AuthError> {
    let seed = seed.as_bytes();
    if seed.len() < SEED_SUBPARTS {
        let e = format!(
            "Improper Seed length of {}. Please supply bigger Seed.",
            seed.len()
        );
        return Err(AuthError::Unexpected(e));
    }

    let interval = seed.len() / SEED_SUBPARTS;

    let mut arr: [&[u8]; SEED_SUBPARTS] = Default::default();
    for (i, val) in arr.iter_mut().enumerate() {
        *val = &seed[interval * i..interval * (i + 1)];
    }

    Ok(arr)
}

/// Creates a random authenticator and login using the same credentials.
pub async fn create_account_and_login() -> Authenticator {
    let (_, locator, password) = create_authenticator().await;

    trace!("Created an account with random login and password, logging in");
    unwrap!(Authenticator::login(locator, password, || ()).await)
}

/// Revokes an app, returning an error on failure.
pub async fn try_revoke(authenticator: &Authenticator, app_id: &str) -> Result<(), AuthError> {
    revocation::revoke_app(&authenticator.client, app_id).await
}

/// Revokes an app, panicking on failure.
pub async fn revoke(authenticator: &Authenticator, app_id: &str) {
    match try_revoke(authenticator, app_id).await {
        Ok(_) => (),
        x => panic!("Unexpected {:?}", x),
    }
}

/// Creates a random authenticator and login using the same credentials.
/// Attaches a hook to the Routing to override responses.
#[cfg(all(any(test, feature = "testing"), feature = "mock-network"))]
pub async fn create_account_and_login_with_hook<F>(hook: F) -> Authenticator
where
    F: Fn(ConnectionManager) -> ConnectionManager + Send + Sync + 'static,
{
    let (_, locator, password) = create_authenticator().await;
    unwrap!(Authenticator::login_with_hook(locator, password, || (), hook,).await)
}

/// Returns `AppInfo` iff the app is listed in the authenticator config.
pub async fn get_app_or_err(
    authenticator: &Authenticator,
    app_id: &str,
) -> Result<config::AppInfo, AuthError> {
    let app_id = app_id.to_string();
    let client = authenticator.client.clone();

    config::get_app(&client, &app_id).await
}

/// Registers a mock application using a given `AuthReq`.
pub async fn register_app(
    authenticator: &Authenticator,
    auth_req: &AuthReq,
) -> Result<AuthGranted, AuthError> {
    let req_id = ipc::gen_req_id();
    let msg = IpcMsg::Req {
        req_id,
        request: IpcReq::Auth(auth_req.clone()),
    };

    // Invoke `decode_ipc_msg` and expect to get AuthReq back.
    let client = authenticator.client.clone();
    let client_clone = client.clone();
    let ipc_req = decode_ipc_msg(&client_clone, msg).await?;

    match ipc_req {
        Ok(IpcMsg::Req {
            request: IpcReq::Auth(_),
            ..
        }) => (),
        x => return Err(AuthError::Unexpected(format!("Unexpected {:?}", x))),
    };

    let auth_req = auth_req.clone();
    trace!("Authenticating app: {:?}", auth_req);
    app_auth::authenticate(&client_clone.clone(), auth_req).await
}

/// Registers a random app. Returns the ID of the app and the `AuthGranted` struct.
#[allow(clippy::implicit_hasher)]
pub async fn register_rand_app(
    authenticator: &Authenticator,
    app_container: bool,
    containers_req: HashMap<String, ContainerPermissions>,
) -> Result<(String, AuthGranted), AuthError> {
    let auth_req = AuthReq {
        app: rand_app(),
        app_container,
        app_permissions: AppPermissions {
            transfer_money: true,
            perform_mutations: true,
            get_balance: true,
        },
        containers: containers_req,
    };

    let auth_granted = register_app(authenticator, &auth_req).await?;
    let app_id = auth_req.app.id;

    Ok((app_id, auth_granted))
}

/// Creates a random `AppExchangeInfo`
pub fn rand_app() -> AppExchangeInfo {
    AppExchangeInfo {
        id: unwrap!(utils::generate_readable_string(10)),
        scope: None,
        name: unwrap!(utils::generate_readable_string(10)),
        vendor: unwrap!(utils::generate_readable_string(10)),
    }
}

/// Creates file in the given container, with the given name and content.
pub async fn create_file<S: Into<String>>(
    authenticator: &Authenticator,
    container_info: MDataInfo,
    name: S,
    content: Vec<u8>,
    published: bool,
) -> Result<(), AuthError> {
    let name = name.into();
    let client = authenticator.client.clone();

    let c2 = client.clone();

    let writer = file_helper::write(
        client.clone(),
        File::new(vec![], published),
        Mode::Overwrite,
        container_info.enc_key().cloned(),
    )
    .await?;

    writer.write(&content).await?;
    let file = writer.close().await?;

    file_helper::insert(c2, container_info, name, &file)
        .await
        .map_err(From::from)
}

/// Fetches file from the given directory by given name.
pub async fn fetch_file<S: Into<String>>(
    authenticator: &Authenticator,
    container_info: MDataInfo,
    name: S,
) -> Result<File, AuthError> {
    let name = name.into();
    let client = authenticator.client.clone();

    let cloned_client = client.clone();
    let (_, file) = file_helper::fetch(cloned_client, container_info, name)
        .await
        .map_err(AuthError::from)?;

    Ok(file)
}

/// Reads from the given file.
pub async fn read_file(
    authenticator: &Authenticator,
    file: File,
    encryption_key: Option<shared_secretbox::Key>,
) -> Result<Vec<u8>, AuthError> {
    let client = authenticator.client.clone();

    let reader = file_helper::read(client.clone(), &file, encryption_key).await?;
    reader
        .read(0, reader.size().await)
        .await
        .map_err(AuthError::from)
}

/// Deletes file from the given directory by given name.
pub async fn delete_file<S: Into<String>>(
    authenticator: &Authenticator,
    container_info: MDataInfo,
    name: S,
    published: bool,
    version: u64,
) -> Result<u64, AuthError> {
    let name = name.into();
    let client = authenticator.client.clone();
    file_helper::delete(
        client,
        container_info,
        name,
        published,
        Version::Custom(version),
    )
    .await
    .map_err(From::from)
}

/// Writes to the given file.
pub async fn write_file(
    authenticator: &Authenticator,
    file: File,
    mode: Mode,
    encryption_key: Option<shared_secretbox::Key>,
    content: Vec<u8>,
) -> Result<(), AuthError> {
    let client = authenticator.client.clone();

    let writer = file_helper::write(client, file, mode, encryption_key).await?;
    match writer.write(&content).await {
        Ok(_) => {
            let _ = writer.close().await?;
            Ok(())
        }
        Err(err) => Err(AuthError::from(err)),
    }
}

/// Fetch the access container entry for the app.
pub async fn access_container<S: Into<String>>(
    authenticator: &Authenticator,
    app_id: S,
    auth_granted: AuthGranted,
) -> Result<AccessContainerEntry, AuthError> {
    match try_access_container(authenticator, app_id, auth_granted).await? {
        Some(container) => Ok(container),
        None => Err(AuthError::from(
            "Access container entry is empty".to_string(),
        )),
    }
}

/// Fetch the access container entry for the app.
pub async fn try_access_container<S: Into<String>>(
    authenticator: &Authenticator,
    app_id: S,
    auth_granted: AuthGranted,
) -> Result<Option<AccessContainerEntry>, AuthError> {
    let app_keys = auth_granted.app_keys;
    let app_id = app_id.into();
    let client = authenticator.client.clone();

    let (_, entry) = access_container::fetch_entry(client, app_id, app_keys).await?;
    Ok(entry)
}

/// Get the container `MDataInfo` from the authenticator entry in the access container.
pub async fn get_container_from_authenticator_entry(
    client: &AuthClient,
    container: &str,
) -> Result<MDataInfo, AuthError> {
    let result = access_container::fetch_authenticator_entry(client).await;

    match result {
        Ok((_, mut ac_entries)) => ac_entries.remove(container).ok_or_else(|| {
            AuthError::from(format!("'{}' not found in the access container", container))
        }),
        Err(err) => Err(err),
    }
}

/// Check that the given permission set is contained in the access container
#[allow(clippy::implicit_hasher)]
pub async fn compare_access_container_entries(
    authenticator: &Authenticator,
    app_pk: PublicKey,
    mut access_container: AccessContainerEntry,
    expected: HashMap<String, ContainerPermissions>,
) {
    let client = &authenticator.client;

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

        let perms = unwrap!(
            client
                .list_mdata_user_permissions(*md_info.address(), user)
                .await
        );

        reqs.push((perms, expected_perm_set));
    }

    // Check the permission on the mutable data for each of the above directories.
    for (perms, expected) in reqs {
        assert_eq!(perms, expected);
    }
}

/// Create random registered client and run it inside an event loop. Use this to
/// create an `AuthClient` automatically and randomly.
pub fn random_client<E, C>(
) -> Result<(Box<dyn Future<Output = ()> + 'static + Send>, AuthClient), AuthError>
where
    E: Debug,
{
    let n = |net_event| panic!("Unexpected NetworkEvent occurred: {:?}", net_event);
    random_client_with_net_obs(n)
}

/// Create random registered client and run it inside an event loop. Use this to
/// create an `AuthClient` automatically and randomly.
pub fn random_client_with_net_obs<NetObs>(
    n: NetObs,
) -> Result<(Box<dyn Future<Output = ()> + 'static + Send>, AuthClient), AuthError>
where
    NetObs: FnMut(NetworkEvent) + Send + 'static,
{
    let client_creator = |net_tx| -> Result<AuthClient, AuthError> {
        let acc_locator = utils::generate_random_string(10)?;
        let acc_password = utils::generate_random_string(10)?;
        let client_id = gen_client_id();

        // block on for test cretion at the moment
        let _ =
            futures::executor::block_on(test_create_balance(&client_id, Money::from_str("10")?));

        let auth_result: AuthClient = futures::executor::block_on(AuthClient::registered(
            &acc_locator,
            &acc_password,
            client_id,
            net_tx,
        ))?;
        Ok(auth_result)
    };

    setup_client_with_net_obs(&(), client_creator, n).map_err(AuthError::from)
}

#[cfg(feature = "mock-network")]
/// Try to revoke apps with the given ids, but simulate network failure so they
/// would be initiated but not finished.
pub async fn simulate_revocation_failure<T, S>(locator: &str, password: &str, app_ids: T)
where
    T: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    // First, log in normally to obtain the access contained info.
    let auth = unwrap!(Authenticator::login(locator, password, || ()).await);
    let client = auth.client;
    let ac_info = client.access_container().await;

    // Then, log in with a request hook that makes mutation of the access container fail.
    let auth = unwrap!(
        Authenticator::login_with_hook(
            locator,
            password,
            || (),
            move |mut cm| -> ConnectionManager {
                let ac_info = ac_info.clone();

                cm.set_request_hook(move |request| match *request {
                    Request::MData(MDataRequest::DelUserPermissions { address, .. }) => {
                        if *address.name() == ac_info.name() && address.tag() == ac_info.type_tag()
                        {
                            Some(Response::Mutation(Err(SndError::InsufficientBalance)))
                        } else {
                            None
                        }
                    }
                    _ => None,
                });
                cm
            },
        )
        .await
    );

    // Then attempt to revoke each app from the iterator.
    for app_id in app_ids {
        match try_revoke(&auth, app_id.as_ref()).await {
            Err(_) => (),
            x => panic!("Unexpected {:?}", x),
        }
    }
}
