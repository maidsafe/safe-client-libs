// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0.
// This, along with the Licenses can be found in the root directory of this
// project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

use app::{App, AppContext};
use app::errors::AppError;
use app::object_cache::MDataInfoHandle;
use core::{Client, FutureExt, MDataInfo};
use futures::Future;
use std::fmt::Debug;
use std::os::raw::c_void;
use util::ffi::OpaqueCtx;
use util::ffi::callback::{Callback, CallbackArgs};

// Convenience wrapper around `App::send` which automatically handles the callback
// boilerplate.
// Use this if the lambda never returns future.
pub unsafe fn send_sync<C, F>(app: *const App,
                              user_data: *mut c_void,
                              o_cb: C,
                              f: F)
                              -> Result<(), AppError>
    where C: Callback + Copy + Send + 'static,
          F: FnOnce(&AppContext) -> Result<C::Args, AppError> + Send + 'static
{
    let user_data = OpaqueCtx(user_data);

    (*app).send(move |_, context| {
        match f(context) {
            Ok(args) => o_cb.call(user_data.0, 0, args),
            Err(err) => o_cb.call(user_data.0, ffi_error_code!(err), C::Args::default()),
        }

        None
    })
}

// Helper to reduce boilerplate when sending asynchronous operations to the app
// event loop.
pub unsafe fn send_with_mdata_info<C, F, U, E>(app: *const App,
                                               info_h: MDataInfoHandle,
                                               user_data: *mut c_void,
                                               cb: C,
                                               f: F)
                                               -> Result<(), AppError>
    where C: Callback + Copy + Send + 'static,
          F: FnOnce(&Client, &AppContext, &MDataInfo) -> U + Send + 'static,
          U: Future<Item = C::Args, Error = E> + 'static,
          E: Debug + 'static,
          AppError: From<E>
{
    let user_data = OpaqueCtx(user_data);

    (*app).send(move |client, context| {
        let info = try_cb!(context.object_cache().get_mdata_info(info_h), user_data, cb);
        f(client, context, &*info)
            .map(move |args| cb.call(user_data.0, 0, args))
            .map_err(AppError::from)
            .map_err(move |err| cb.call(user_data.0, ffi_error_code!(err), C::Args::default()))
            .into_box()
            .into()
    })
}
