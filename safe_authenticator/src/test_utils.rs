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
use crate::{access_container, app_auth, config, revocation, run, Authenticator};
use env_logger::{fmt::Formatter, Builder as LoggerBuilder};
use futures_util::future::FutureExt;
use futures::{future, future::IntoFuture, Future};
use futures_util::future::TryFutureExt;
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
use safe_nd::{AppPermissions, Coins, PublicKey, XorName};
#[cfg(feature = "mock-network")]
use safe_nd::{Error as SndError, Request, Response, UnseqMutableData};
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::Write;
use std::str::FromStr;
use unwrap::unwrap;

const FAKE_FILES_TAG_TYPE: u64 = 112;

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
    let locator: String = unwrap!(utils::generate_readable_string(10));
    let password: String = unwrap!(utils::generate_readable_string(10));
    let client_id = gen_client_id();

    futures::executor::block_on(test_create_balance(
        &client_id,
        unwrap!(Coins::from_str("100")),
    ));

    let auth = unwrap!(Authenticator::create_acc(
        locator.clone(),
        password.clone(),
        client_id,
        || (),
    ));

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
pub fn create_account_and_login() -> Authenticator {
    let (_, locator, password) = create_authenticator();

    trace!("Created an account with random login and password, logging in");
    unwrap!(Authenticator::login(locator, password, || ()))
}

/// Revokes an app, returning an error on failure.
pub fn try_revoke(authenticator: &Authenticator, app_id: &str) -> Result<(), AuthError> {
    let app_id = app_id.to_string();

    run(authenticator, move |client| {
        let client_clone_ref = &client.clone();
        revocation::revoke_app(client_clone_ref, &app_id)
    })
}

/// Revokes an app, panicking on failure.
pub fn revoke(authenticator: &Authenticator, app_id: &str) {
    match try_revoke(authenticator, app_id) {
        Ok(_) => (),
        x => panic!("Unexpected {:?}", x),
    }
}

/// Creates a random authenticator and login using the same credentials.
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
        let client_clone_ref = &client.clone();

        config::get_app(client_clone_ref, &app_id)
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
        request: IpcReq::Auth(auth_req.clone()),
    };

    // Invoke `decode_ipc_msg` and expect to get AuthReq back.
    let ipc_req = run(authenticator, move |client| {
        // async {
        let client_clone = client.clone();
        decode_ipc_msg(&client_clone, msg)
        // ).await
        // }
    })?;

    match ipc_req {
        Ok(IpcMsg::Req {
            request: IpcReq::Auth(_),
            ..
        }) => (),
        x => return Err(AuthError::Unexpected(format!("Unexpected {:?}", x))),
    }

    let auth_req = auth_req.clone();
    run(authenticator, move |client| {
        trace!("Authenticating app: {:?}", auth_req);
        let client_clone = client.clone();
        app_auth::authenticate(&client_clone, auth_req)
    })
}

/// Registers a random app. Returns the ID of the app and the `AuthGranted` struct.
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
            perform_mutations: true,
            get_balance: true,
        },
        containers: containers_req,
    };

    let auth_granted = register_app(authenticator, &auth_req)?;
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
    let file = run(authenticator, |client| {
        // simple test help for pseudo file system....
        // Tests are all about permissions rather than files themselves.
        // NFS support in core is GONE. so just putting MD.
        // TODO update naming to be clearer about just putting MD.
    
        // let result: Future<Output=Result<Option<u8>, AuthError>> = async {

            // let (_, file) = 
            
            let cloned_client = client.clone();
            async {
                file_helper::fetch(cloned_client, container_info, name).await
    
                    .map(|(_, file)| file)
                    .map_err(AuthError::from)
                    //     Ok(file) => file,

            }
                //     Err(error) => return error
                // }
        // };

        // result
            // .map_err(From::from)
    });

    match file {
        Ok(file) => Ok(file),
        Err(error) => Err(error)
    }
}

/// Reads from the given file.
pub fn read_file(
    authenticator: &Authenticator,
    file: File,
    // file: File,
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

    // Ok(1)
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

    // Ok(1)
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
        let cloned_client = client.clone();
        async {
            let res = file_helper::write(cloned_client, file, mode, encryption_key).await;
            let writer = unwrap!(res);
            match writer
                .write(&content).await
                // .map_err(From::from) {
                    {
                    Ok(_) => {
                        writer.close().await;
                        Ok(())
                    },
                    Err(err) => Err(AuthError::from(err))
                }

                // .and_then(move |_| writer.close().map(|_| ()))

        }
            // .then(move |res| {
            // })
    })

    // Ok(())
}

/// Fetch the access container entry for the app.
pub async fn access_container<S: Into<String>>(
    authenticator: &Authenticator,
    app_id: S,
    auth_granted: AuthGranted,
) -> AccessContainerEntry {
    unwrap!(
        try_access_container(authenticator, app_id, auth_granted).await,
        "Access container entry is empty"
    )
}

/// Fetch the access container entry for the app.
pub async fn try_access_container<S: Into<String>>(
    authenticator: &Authenticator,
    app_id: S,
    auth_granted: AuthGranted,
) -> Option<AccessContainerEntry> {
    let app_keys = auth_granted.app_keys;
    let app_id = app_id.into();
    unwrap!(run(authenticator, move |client| {
        let client_clone = client.clone();
        async {
            let entry = access_container::fetch_entry(client_clone, app_id, app_keys).await;
            entry.map(move |(_, entry)| entry)
        }
    }))
}

/// Get the container `MDataInfo` from the authenticator entry in the access container.
pub fn get_container_from_authenticator_entry(
    authenticator: &Authenticator,
    container: String,
) ->  Result<MDataInfo, AuthError> {
    
    run(
        authenticator.clone(),
        | client| 
        {
          
            // TODO: We're gonna be removing this sort of enforced event loop and make it supplied by the lib

            // async {
                access_container::fetch_authenticator_entry(&client).then(|result| {
    
                    match result {
                        Ok((_, ac_entries) ) => {
                            ac_entries.remove(&container.clone()).ok_or_else(|| {
                                AuthError::from(format!("'{}' not found in the access container", container))
                            })
                        },
                        Err(err) => Err(err)
                            //  {
                            //     Ok(a) => a,
                            //     Err(error) => return Err(error)
                            // }
                    }

                })
               
    })?
}

/// Check that the given permission set is contained in the access container
#[allow(clippy::implicit_hasher)]
pub async fn compare_access_container_entries(
    authenticator: &Authenticator,
    app_pk: PublicKey,
    mut access_container: AccessContainerEntry,
    expected: HashMap<String, ContainerPermissions>,
) {
    let results = unwrap!(run(authenticator, move |client| {
        // have i borked this func???
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

            async {
                let perms = unwrap!(
                    client
                        .list_mdata_user_permissions(*md_info.address(), user)
                        .await
                );
                // futures::executor::block_on(
                //  );

                reqs.push((perms, expected_perm_set));
            };
        }
        async { Ok(reqs) }
        // future::join_all(reqs).map_err(AuthError::from)
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
    I: Future<Output = Result<T, E>> + Send + Sync + 'static,
    T: Send + Sync + 'static,
    E: Debug,
{
    let n = |net_event| panic!("Unexpected NetworkEvent occurred: {:?}", net_event);
    random_client_with_net_obs(n, r)
}

/// Create random registered client and run it inside an event loop. Use this to
/// create an `AuthClient` automatically and randomly.
pub fn random_client_with_net_obs<NetObs, Run, I, T, E>(n: NetObs, r: Run) -> T
//<T as core::future::future::Future>::Output
where
    NetObs: FnMut(NetworkEvent) + Send + 'static,
    Run: FnOnce(&AuthClient) -> I + Send + 'static,
    I: Future<Output = Result<T, E>> + Send + Sync + 'static,
    T: Send + Sync + 'static,
    E: Debug, // <T as core::future::future::Future>::Output,
{
    let c = |el_h, core_tx, net_tx| -> Result<AuthClient, AuthError> {
        let acc_locator = unwrap!(utils::generate_random_string(10));
        let acc_password = unwrap!(utils::generate_random_string(10));
        let client_id = gen_client_id();

        futures::executor::block_on(test_create_balance(
            &client_id,
            unwrap!(Coins::from_str("10")),
        ));

        let auth_result: AuthClient = futures::executor::block_on(AuthClient::registered(
            &acc_locator,
            &acc_password,
            client_id,
            el_h,
            core_tx,
            net_tx,
        ))?;
        Ok(auth_result)
    };

    // c = futures::executor::block_on( c() );
    // futures::executor::block_on(
    setup_client_with_net_obs(&(), c, n, r)
    // )
}

#[cfg(feature = "mock-network")]
/// Try to revoke apps with the given ids, but simulate network failure so they
/// would be initiated but not finished.
pub fn simulate_revocation_failure<T, S>(locator: &str, password: &str, app_ids: T)
where
    T: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    // First, log in normally to obtain the access contained info.
    let auth = unwrap!(Authenticator::login(locator, password, || ()));
    let ac_info = unwrap!(run(&auth, |client| Ok(client.access_container())));

    // Then, log in with a request hook that makes mutation of the access container
    // fail.
    let auth = unwrap!(Authenticator::login_with_hook(
        locator,
        password,
        || (),
        move |mut cm| -> ConnectionManager {
            let ac_info = ac_info.clone();

            cm.set_request_hook(move |request| match *request {
                Request::DelMDataUserPermissions { address, .. } => {
                    if *address.name() == ac_info.name() && address.tag() == ac_info.type_tag() {
                        Some(Response::Mutation(Err(SndError::InsufficientBalance)))
                    } else {
                        None
                    }
                }
                _ => None,
            });
            cm
        },
    ));

    // Then attempt to revoke each app from the iterator.
    for app_id in app_ids {
        match try_revoke(&auth, app_id.as_ref()) {
            Err(_) => (),
            x => panic!("Unexpected {:?}", x),
        }
    }
}
