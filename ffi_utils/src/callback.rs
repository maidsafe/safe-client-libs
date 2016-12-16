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

//! Helpers to work with extern "C" callbacks.

use std::os::raw::c_void;
use std::ptr;
use super::string::FfiString;

/// This trait allows us to treat callbacks with different number and type of
/// arguments uniformly.
pub trait Callback {
    /// Arguments for the callback. Should be a tuple.
    type Args: CallbackArgs;

    /// Call the callback, passing the user data pointer, error code and any
    /// additional arguments.
    fn call(&self, user_data: *mut c_void, error: i32, args: Self::Args);
}

impl Callback for extern "C" fn(*mut c_void, i32) {
    type Args = ();
    fn call(&self, user_data: *mut c_void, error: i32, _args: Self::Args) {
        self(user_data, error)
    }
}

impl<T: CallbackArgs> Callback for extern "C" fn(*mut c_void, i32, a: T) {
    type Args = T;
    fn call(&self, user_data: *mut c_void, error: i32, args: Self::Args) {
        self(user_data, error, args)
    }
}

impl<T0: CallbackArgs, T1: CallbackArgs> Callback
    for extern "C" fn(*mut c_void, i32, a0: T0, a1: T1) {
    type Args = (T0, T1);
    fn call(&self, user_data: *mut c_void, error: i32, args: Self::Args) {
        self(user_data, error, args.0, args.1)
    }
}

impl<T0: CallbackArgs, T1: CallbackArgs, T2: CallbackArgs> Callback
    for extern "C" fn(*mut c_void, i32, a0: T0, a1: T1, a2: T2) {
    type Args = (T0, T1, T2);
    fn call(&self, user_data: *mut c_void, error: i32, args: Self::Args) {
        self(user_data, error, args.0, args.1, args.2)
    }
}

impl<T0: CallbackArgs, T1: CallbackArgs, T2: CallbackArgs, T3: CallbackArgs> Callback
    for extern "C" fn(*mut c_void, i32, a0: T0, a1: T1, a2: T2, a3: T3) {
    type Args = (T0, T1, T2, T3);
    fn call(&self, user_data: *mut c_void, error: i32, args: Self::Args) {
        self(user_data, error, args.0, args.1, args.2, args.3)
    }
}

/// Trait for arguments to callbacks. This is similar to `Default`, but allows
/// us to implement it for foreign types that don't already implement `Default`.
pub trait CallbackArgs {
    /// Return default value for the type, used when calling the callback with error.
    fn default() -> Self;
}

impl CallbackArgs for () {
    fn default() -> Self {
        ()
    }
}

impl CallbackArgs for bool {
    fn default() -> Self {
        false
    }
}

impl CallbackArgs for u32 {
    fn default() -> Self {
        0
    }
}

impl CallbackArgs for i64 {
    fn default() -> Self {
        0
    }
}

impl CallbackArgs for u64 {
    fn default() -> Self {
        0
    }
}

impl CallbackArgs for usize {
    fn default() -> Self {
        0
    }
}

impl<T> CallbackArgs for *const T {
    fn default() -> Self {
        ptr::null()
    }
}

impl<T> CallbackArgs for *mut T {
    fn default() -> Self {
        ptr::null_mut()
    }
}

impl CallbackArgs for [u8; 32] {
    fn default() -> Self {
        [0; 32]
    }
}

impl CallbackArgs for FfiString {
    fn default() -> Self {
        Default::default()
    }
}

impl<T0: CallbackArgs, T1: CallbackArgs> CallbackArgs for (T0, T1) {
    fn default() -> Self {
        (CallbackArgs::default(), CallbackArgs::default())
    }
}

impl<T0: CallbackArgs, T1: CallbackArgs, T2: CallbackArgs> CallbackArgs for (T0, T1, T2) {
    fn default() -> Self {
        (CallbackArgs::default(), CallbackArgs::default(), CallbackArgs::default())
    }
}

impl<T0: CallbackArgs, T1: CallbackArgs, T2: CallbackArgs, T3: CallbackArgs> CallbackArgs
    for (T0, T1, T2, T3) {
    fn default() -> Self {
        (CallbackArgs::default(),
         CallbackArgs::default(),
         CallbackArgs::default(),
         CallbackArgs::default())
    }
}
