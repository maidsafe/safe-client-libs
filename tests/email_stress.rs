// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, unicode_not_nfc, wrong_pub_self_convention,
                                   option_unwrap_used))]
#![cfg_attr(feature="clippy", allow(use_debug, doc_markdown))] // TODO: Fix doc_markdown errors.

/* TODO (adam): uncomment this

#[macro_use]
extern crate log;
#[macro_use]
extern crate unwrap;

extern crate crossbeam;
extern crate rust_sodium;
extern crate safe_core;

use rust_sodium::crypto::hash::sha256::{self, Digest};
use safe_core::core::utility;
use safe_core::ffi::app::*;
use safe_core::ffi::logging::*;
use safe_core::ffi::low_level_api::{AppendableDataHandle, CipherOptHandle};
use safe_core::ffi::low_level_api::appendable_data::*;
use safe_core::ffi::low_level_api::cipher_opt::*;
use safe_core::ffi::low_level_api::data_id::*;
use safe_core::ffi::low_level_api::immut_data::*;
use safe_core::ffi::low_level_api::misc::*;
use safe_core::ffi::session::*;
use std::{ptr, slice};
use std::sync::Mutex;
use std::time::Instant;

const BOTS: usize = 5;
const MSGS_SENT_BY_EACH_BOT: usize = 5;

struct Bot {
    app_h: *mut App,
    session_h: *mut SessionHandle,
    email: String,
    tx_msgs: Vec<Vec<u8>>,
}

impl Bot {
    fn new(n: usize) -> Self {
        let mut app_h: *mut App = ptr::null_mut();
        let mut session_h: *mut SessionHandle = ptr::null_mut();

        let sec_0 = unwrap!(utility::generate_random_string(10));
        let sec_1 = unwrap!(utility::generate_random_string(10));

        unsafe {
            assert_eq!(create_account(sec_0.as_bytes().as_ptr(),
                                      sec_0.as_bytes().len(),
                                      sec_1.as_bytes().as_ptr(),
                                      sec_1.as_bytes().len(),
                                      &mut session_h),
                       0);
        }

        let app_name = format!("Bot-{}", n);
        let unique_token = format!("Bot-{}", n);
        let vendor = "MaidSafe".to_string();

        unsafe {
            assert_eq!(register_app(session_h,
                                    app_name.as_bytes().as_ptr(),
                                    app_name.as_bytes().len(),
                                    unique_token.as_bytes().as_ptr(),
                                    unique_token.as_bytes().len(),
                                    vendor.as_bytes().as_ptr(),
                                    vendor.as_bytes().len(),
                                    false,
                                    &mut app_h),
                       0);
        }

        // Without this the test will fail the next time it is run.
        let prefix = unwrap!(utility::generate_random_string(10));
        let email = format!("{}-Bot-{}-mail", prefix, n);

        Bot {
            app_h: app_h,
            session_h: session_h,
            email: email,
            tx_msgs: (0..MSGS_SENT_BY_EACH_BOT)
                .map(|_| unwrap!(utility::generate_random_vector::<u8>(10)))
                .collect(),
        }
    }

    fn create_email(&self) {
        let Digest(digest) = sha256::hash(self.email.as_bytes());

        let mut ad_h = 0;
        unsafe {
            assert_eq!(appendable_data_new_priv(self.app_h, &digest, &mut ad_h), 0);
            assert_eq!(appendable_data_put(self.app_h, ad_h), 0);
        }
        assert_eq!(appendable_data_free(ad_h), 0);
    }

    fn get_peer_email_handles(&self, peer_email: &str) -> (AppendableDataHandle, CipherOptHandle) {
        let Digest(digest) = sha256::hash(peer_email.as_bytes());
        let mut data_id_h = 0;
        unsafe {
            assert_eq!(data_id_new_appendable_data(&digest, true, &mut data_id_h),
                       0);
        }

        let mut ad_h = 0;
        unsafe {
            assert_eq!(appendable_data_get(self.app_h, data_id_h, &mut ad_h), 0);
        }
        assert_eq!(data_id_free(data_id_h), 0);

        let mut cipher_opt_h = 0;
        let mut encrypt_key_h = 0;
        unsafe {
            assert_eq!(appendable_data_encrypt_key(ad_h, &mut encrypt_key_h), 0);
            assert_eq!(cipher_opt_new_asymmetric(encrypt_key_h, &mut cipher_opt_h),
                       0);
        }
        assert_eq!(misc_encrypt_key_free(encrypt_key_h), 0);

        (ad_h, cipher_opt_h)
    }

    fn send_email(&self, peer_ad_h: u64, cipher_opt_h: u64, msg: &[u8]) {
        let mut se_h = 0;
        unsafe {
            assert_eq!(immut_data_new_self_encryptor(self.app_h, &mut se_h), 0);
            assert_eq!(immut_data_write_to_self_encryptor(se_h, msg.as_ptr(), msg.len()),
                       0);
        }

        let mut data_id_h = 0;
        unsafe {
            assert_eq!(immut_data_close_self_encryptor(self.app_h,
                                                       se_h,
                                                       cipher_opt_h,
                                                       &mut data_id_h),
                       0);
            assert_eq!(appendable_data_append(self.app_h, peer_ad_h, data_id_h), 0);
        }

        assert_eq!(data_id_free(data_id_h), 0);
        assert_eq!(immut_data_self_encryptor_writer_free(se_h), 0);
    }

    fn get_all_emails(&self) -> Vec<Vec<u8>> {
        let Digest(digest) = sha256::hash(self.email.as_bytes());

        let mut data_id_h = 0;
        unsafe {
            assert_eq!(data_id_new_appendable_data(&digest, true, &mut data_id_h),
                       0);
        }

        let mut ad_h = 0;
        unsafe {
            assert_eq!(appendable_data_get(self.app_h, data_id_h, &mut ad_h), 0);
        }
        assert_eq!(data_id_free(data_id_h), 0);

        let mut num_of_emails = 0;
        unsafe {
            assert_eq!(appendable_data_num_of_data(ad_h, &mut num_of_emails), 0);
        }

        let mut rx_msgs = Vec::with_capacity(num_of_emails);

        for n in 0..num_of_emails {
            unsafe {
                assert_eq!(appendable_data_nth_data_id(self.app_h, ad_h, n, &mut data_id_h),
                           0);
            }

            let mut se_h = 0;
            unsafe {
                assert_eq!(immut_data_fetch_self_encryptor(self.app_h, data_id_h, &mut se_h),
                           0);
            }

            let mut total_size = 0;
            unsafe {
                assert_eq!(immut_data_size(se_h, &mut total_size), 0);
            }

            let mut data_ptr: *mut u8 = ptr::null_mut();
            let mut read_size = 0;
            let mut capacity = 0;
            unsafe {
                assert_eq!(immut_data_read_from_self_encryptor(se_h,
                                                               0,
                                                               total_size,
                                                               &mut data_ptr,
                                                               &mut read_size,
                                                               &mut capacity),
                           0);
            }

            // TODO Confirm that cloning is done - else this is UB as we are freeing the vector
            // separately.
            let rx_msg = unsafe { slice::from_raw_parts(data_ptr, read_size).to_owned() };
            rx_msgs.push(rx_msg);

            assert_eq!(data_id_free(data_id_h), 0);
            assert_eq!(immut_data_self_encryptor_reader_free(se_h), 0);
            unsafe {
                misc_u8_ptr_free(data_ptr, read_size, capacity);
            }
        }

        assert_eq!(appendable_data_free(ad_h), 0);

        rx_msgs
    }
}

impl Drop for Bot {
    fn drop(&mut self) {
        unsafe {
            drop_app(self.app_h);
            drop_session(self.session_h);
        }
    }
}

unsafe impl Send for Bot {}
unsafe impl Sync for Bot {}

#[test]
fn email_stress() {
    assert_eq!(init_logging(), 0);

    // ------------------------------------------------------------------------
    // Create bots
    let mut now = Instant::now();
    let bots: Vec<_> = (0..BOTS).map(|n| Bot::new(n)).collect();
    let mut duration = now.elapsed();
    info!("Create accounts for {} bots: {} secs, {} millis\n",
          BOTS,
          duration.as_secs(),
          duration.subsec_nanos() / 1000000);

    // ------------------------------------------------------------------------
    // Create email in parallel
    now = Instant::now();
    crossbeam::scope(|scope| {
        for bot in &bots {
            let _ = scope.spawn(move || bot.create_email());
        }
    });
    duration = now.elapsed();
    info!("Create emails for {} bots: {} secs, {} millis\n",
          BOTS,
          duration.as_secs(),
          duration.subsec_nanos() / 1000000);

    // ------------------------------------------------------------------------
    // Send emails
    now = Instant::now();
    for (i, bot) in bots.iter().enumerate() {
        let peer_handles = Mutex::new(Vec::with_capacity(BOTS - 1));
        let peer_handles_ref = &peer_handles;

        // Get peer emails in parallel
        crossbeam::scope(|scope| {
            for (j, peer_bot) in bots.iter().enumerate() {
                if i == j {
                    continue;
                }
                let _ = scope.spawn(move || {
                    unwrap!(peer_handles_ref.lock())
                        .push(bot.get_peer_email_handles(&peer_bot.email))
                });
            }
        });

        // Send each email-msg from a bot in parallel to all others
        for msg in &bot.tx_msgs {
            let guard = unwrap!(peer_handles.lock());
            crossbeam::scope(|scope| {
                for &(ad_h, cipher_opt_h) in &*guard {
                    let _ = scope.spawn(move || bot.send_email(ad_h, cipher_opt_h, msg));
                }
            })
        }

        let guard = unwrap!(peer_handles.lock());
        for &(ad_h, cipher_opt_h) in &*guard {
            assert_eq!(appendable_data_free(ad_h), 0);
            assert_eq!(cipher_opt_free(cipher_opt_h), 0);
        }
    }
    duration = now.elapsed();
    info!("Send total of {} emails by {} bots: {} secs, {} millis\n",
          MSGS_SENT_BY_EACH_BOT * (BOTS - 1),
          BOTS,
          duration.as_secs(),
          duration.subsec_nanos() / 1000000);

    // ------------------------------------------------------------------------
    // Read and verify all emails by all bots in parallel
    now = Instant::now();
    crossbeam::scope(|scope| {
        let bots_ref = &bots;

        for (i, bot) in bots_ref.iter().enumerate() {
            let _ = scope.spawn(move || {
                let mut rx_emails = bot.get_all_emails();
                assert_eq!(rx_emails.len(), MSGS_SENT_BY_EACH_BOT * (BOTS - 1));

                for (j, peer_bot) in bots_ref.iter().enumerate() {
                    if i == j {
                        continue;
                    }
                    for tx_msg in &peer_bot.tx_msgs {
                        let pos = unwrap!(rx_emails.iter()
                            .position(|rx_email| *rx_email == *tx_msg));
                        let _ = rx_emails.remove(pos);
                    }
                }
            });
        }
    });
    duration = now.elapsed();
    info!("Read total of {} emails by {} bots: {} secs, {} millis\n",
          MSGS_SENT_BY_EACH_BOT * (BOTS - 1),
          BOTS,
          duration.as_secs(),
          duration.subsec_nanos() / 1000000);

}

*/
