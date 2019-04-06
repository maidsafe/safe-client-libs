// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::client::AppClient;
use crate::errors::AppError;
use crate::ffi_utils::callback::Callback;
use crate::ffi_utils::{FfiResult, OpaqueCtx, FFI_RESULT_OK};
use crate::{App, AppContext};
use futures::Future;
use safe_core::FutureExt;
use std::fmt::Debug;
use std::os::raw::c_void;

// Convenience wrapper around `App::send` which automatically handles the callback
// boilerplate.
// Use this if the lambda never returns future.
pub unsafe fn send_sync<C, F>(
    app: *const App,
    user_data: *mut c_void,
    o_cb: C,
    f: F,
) -> Result<(), AppError>
where
    C: Callback + Copy + Send + 'static,
    F: FnOnce(&AppClient, &AppContext) -> Result<C::Args, AppError> + Send + 'static,
{
    let user_data = OpaqueCtx(user_data);

    (*app).send(move |client, context| {
        match f(client, context) {
            Ok(args) => o_cb.call(user_data.0, FFI_RESULT_OK, args),
            res @ Err(..) => {
                call_result_cb!(res, user_data, o_cb);
            }
        }
        None
    })
}

// Helper to reduce boilerplate when sending asynchronous operations to the app
// event loop.
pub unsafe fn send<C, F, U, E>(
    app: *const App,
    user_data: *mut c_void,
    o_cb: C,
    f: F,
) -> Result<(), AppError>
where
    C: Callback + Copy + Send + 'static,
    F: FnOnce(&AppClient, &AppContext) -> U + Send + 'static,
    U: Future<Item = C::Args, Error = E> + 'static,
    E: Debug + 'static,
    AppError: From<E>,
{
    let user_data = OpaqueCtx(user_data);

    (*app).send(move |client, context| {
        f(client, context)
            .map(move |args| o_cb.call(user_data.0, FFI_RESULT_OK, args))
            .map_err(AppError::from)
            .map_err(move |err| {
                call_result_cb!(Err::<(), _>(err), user_data, o_cb);
            })
            .into_box()
            .into()
    })
}
