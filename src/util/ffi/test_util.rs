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

use std::os::raw::c_void;
use std::sync::mpsc::{self, Sender};

// Convert a `mpsc::Sender<T>` to a void ptr which can be passed as user data to
// ffi functions
pub fn sender_as_user_data<T>(tx: &Sender<T>) -> *mut c_void {
    let ptr: *const _ = tx;
    ptr as *mut c_void
}

// Send through a `mpsc::Sender` pointed to by the user data pointer.
pub unsafe fn send_via_user_data<T>(user_data: *mut c_void, value: T)
    where T: Send
{
    let tx = user_data as *mut Sender<T>;
    unwrap!((*tx).send(value));
}

// Call a FFI function and block until its callback gets called.
// Use this if the callback accepts no arguments in addition to user_data
// and error_code.
pub fn call_0<F>(f: F) -> Result<(), i32>
    where F: FnOnce(*mut c_void, extern "C" fn(*mut c_void, i32))
{
    let (tx, rx) = mpsc::channel::<i32>();
    f(sender_as_user_data(&tx), callback_0);

    let error = unwrap!(rx.recv());
    if error == 0 { Ok(()) } else { Err(error) }
}

// Call a FFI function and block until its callback gets called, then return
// the argument which were passed to that callback.
// Use this if the callback accepts one argument in addition to user_data
// and error_code.
pub unsafe fn call_1<F, T>(f: F) -> Result<T, i32>
    where F: FnOnce(*mut c_void, extern "C" fn(*mut c_void, i32, T))
{
    let (tx, rx) = mpsc::channel::<(i32, SendWrapper<T>)>();
    f(sender_as_user_data(&tx), callback_1::<T>);

    let (error, args) = unwrap!(rx.recv());
    if error == 0 { Ok(args.0) } else { Err(error) }
}

// Call a FFI function and block until its callback gets called, then return
// the argument which were passed to that callback.
// Use this if the callback accepts two arguments in addition to user_data
// and error_code.
pub unsafe fn call_2<F, T0, T1>(f: F) -> Result<(T0, T1), i32>
    where F: FnOnce(*mut c_void, extern "C" fn(*mut c_void, i32, T0, T1))
{
    let (tx, rx) = mpsc::channel::<(i32, SendWrapper<(T0, T1)>)>();
    f(sender_as_user_data(&tx), callback_2::<T0, T1>);

    let (error, args) = unwrap!(rx.recv());
    if error == 0 { Ok(args.0) } else { Err(error) }
}

// Call a FFI function and block until its callback gets called, then return
// the arguments which were passed to that callback in a tuple.
// Use this if the callback accepts three arguments in addition to user_data and
// error_code.
pub unsafe fn call_3<F, T0, T1, T2>(f: F) -> Result<(T0, T1, T2), i32>
    where F: FnOnce(*mut c_void, extern "C" fn(*mut c_void, i32, T0, T1, T2))
{
    let (tx, rx) = mpsc::channel::<(i32, SendWrapper<(T0, T1, T2)>)>();
    f(sender_as_user_data(&tx), callback_3::<T0, T1, T2>);

    let (error, args) = unwrap!(rx.recv());
    if error == 0 { Ok(args.0) } else { Err(error) }
}

extern "C" fn callback_0(user_data: *mut c_void, error: i32) {
    unsafe { send_via_user_data(user_data, error) }
}

extern "C" fn callback_1<T>(user_data: *mut c_void, error: i32, arg: T) {
    unsafe { send_via_user_data(user_data, (error, SendWrapper(arg))) }
}

extern "C" fn callback_2<T0, T1>(user_data: *mut c_void, error: i32, arg0: T0, arg1: T1) {
    unsafe { send_via_user_data(user_data, (error, SendWrapper((arg0, arg1)))) }
}

extern "C" fn callback_3<T0, T1, T2>(user_data: *mut c_void,
                                     error: i32,
                                     arg0: T0,
                                     arg1: T1,
                                     arg2: T2) {
    unsafe { send_via_user_data(user_data, (error, SendWrapper((arg0, arg1, arg2)))) }
}

// Unsafe wrapper for passing non-Send types through mpsc channels.
// Use with caution!
struct SendWrapper<T>(T);
unsafe impl<T> Send for SendWrapper<T> {}
