// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

mod nfs;

use super::*;
use ffi_utils::test_utils::call_1;
use routing::ImmutableData;
use safe_core::ffi::AccountInfo;
use test_utils::create_app;

// Test account usage statistics before and after a mutation.
#[test]
fn account_info() {
    let app = create_app();
    let app = Box::into_raw(Box::new(app));

    let orig_stats: AccountInfo =
        unsafe { unwrap!(call_1(|ud, cb| app_account_info(app, ud, cb))) };
    assert!(orig_stats.mutations_available > 0);

    unsafe {
        unwrap!((*app).send(move |client, _| {
            client
                .put_idata(ImmutableData::new(vec![1, 2, 3]))
                .map_err(move |_| ())
                .into_box()
                .into()
        }));
    }

    let stats: AccountInfo = unsafe { unwrap!(call_1(|ud, cb| app_account_info(app, ud, cb))) };
    assert_eq!(stats.mutations_done, orig_stats.mutations_done + 1);
    assert_eq!(
        stats.mutations_available,
        orig_stats.mutations_available - 1
    );

    unsafe { app_free(app) };
}

// Test disconnection and reconnection with apps.
#[cfg(all(test, feature = "use-mock-routing"))]
#[test]
fn network_status_callback() {
    use App;
    use ffi_utils::test_utils::{call_0, send_via_user_data, sender_as_user_data};
    use maidsafe_utilities::serialisation::serialise;
    use safe_core::NetworkEvent;
    use safe_core::ipc::BootstrapConfig;
    use std::os::raw::c_void;
    use std::sync::mpsc;
    use std::time::Duration;

    {
        let (tx, rx) = mpsc::channel();

        let bootstrap_cfg = unwrap!(serialise(&BootstrapConfig::default()));

        let app: *mut App = unsafe {
            unwrap!(call_1(|ud, cb| {
                app_unregistered(
                    bootstrap_cfg.as_ptr(),
                    bootstrap_cfg.len(),
                    sender_as_user_data(&tx),
                    ud,
                    net_event_cb,
                    cb,
                )
            }))
        };

        unsafe {
            unwrap!((*app).send(move |client, _| {
                client.simulate_network_disconnect();
                None
            }));
        }

        let (error_code, event): (i32, i32) = unwrap!(rx.recv_timeout(Duration::from_secs(10)));
        assert_eq!(error_code, 0);

        let disconnected: i32 = NetworkEvent::Disconnected.into();
        assert_eq!(event, disconnected);

        // Reconnect with the network
        unsafe { unwrap!(call_0(|ud, cb| app_reconnect(app, ud, cb))) };

        let (err_code, event): (i32, i32) = unwrap!(rx.recv_timeout(Duration::from_secs(10)));
        assert_eq!(err_code, 0);

        let connected: i32 = NetworkEvent::Connected.into();
        assert_eq!(event, connected);

        // The reconnection should be fine if we're already connected.
        unsafe { unwrap!(call_0(|ud, cb| app_reconnect(app, ud, cb))) };

        let (err_code, event): (i32, i32) = unwrap!(rx.recv_timeout(Duration::from_secs(10)));
        assert_eq!(err_code, 0);
        assert_eq!(event, disconnected);

        let (err_code, event): (i32, i32) = unwrap!(rx.recv_timeout(Duration::from_secs(10)));
        assert_eq!(err_code, 0);
        assert_eq!(event, connected);

        unsafe { app_free(app) };
    }

    extern "C" fn net_event_cb(user_data: *mut c_void, res: FfiResult, event: i32) {
        unsafe {
            send_via_user_data(user_data, (res.error_code, event));
        }
    }
}
