// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#![allow(
    non_snake_case,
    missing_docs,
    unsafe_code,
    unused_results,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    unused_qualifications
)]

#[cfg(target_os = "android")]
extern crate android_logger;
#[macro_use]
extern crate ffi_utils;
extern crate jni;
#[macro_use]
extern crate log;
extern crate safe_authenticator;
extern crate safe_core;
#[macro_use]
extern crate unwrap;

use ffi_utils::java::{convert_cb_from_java, object_array_to_java, EnvGuard, JniResult};
use ffi_utils::*;
use jni::errors::{Error as JniError, ErrorKind};
use jni::objects::{AutoLocal, GlobalRef, JClass, JMethodID, JObject, JString, JValue};
use jni::strings::JNIStr;
use jni::sys::{jbyte, jbyteArray, jint, jlong, jobject, jsize};
use jni::{signature::JavaType, JNIEnv, JavaVM};
use safe_authenticator::*;
use safe_core::arrays::*;
use safe_core::ffi::ipc::req::{
    AppExchangeInfo, AuthReq, ContainerPermissions, ContainersReq, PermissionSet, ShareMData,
    ShareMDataReq,
};
use safe_core::ffi::ipc::resp::{
    AccessContInfo, AccessContainerEntry, AppAccess, AppKeys, AuthGranted, ContainerInfo,
    MDataEntry, MDataKey, MDataValue, MetadataResponse,
};
use safe_core::ffi::nfs::File;
use safe_core::ffi::*;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::{cmp, mem, slice};

#[repr(C)]
struct Authenticator(*mut c_void);

static mut JVM: Option<JavaVM> = None;
static mut CLASS_LOADER: Option<GlobalRef> = None;
static mut FIND_CLASS_METHOD: Option<JMethodID> = None;

// This is called when `loadLibrary` is called on the Java side.
#[no_mangle]
pub unsafe extern "C" fn JNI_OnLoad(vm: *mut jni::sys::JavaVM, _reserved: *mut c_void) -> jint {
    JVM = match JavaVM::from_raw(vm) {
        Ok(vm) => Some(vm),
        Err(e) => {
            error!("{}", e);
            return -1;
        }
    };
    if let Err(e) = cache_class_loader() {
        error!("{}", e);
        return -1;
    }
    jni::sys::JNI_VERSION_1_4
}

#[cfg(not(target_os = "android"))]
unsafe fn cache_class_loader() -> Result<(), JniError> {
    Ok(())
}

#[cfg(target_os = "android")]
unsafe fn cache_class_loader() -> Result<(), JniError> {
    let env = JVM
        .as_ref()
        .ok_or_else(|| From::from("no JVM reference found"))
        .and_then(|vm| vm.get_env())?;

    let res_class = env.find_class("net/maidsafe/safe_authenticator/FfiResult")?;

    CLASS_LOADER = Some(
        env.new_global_ref(
            env.call_method(
                From::from(res_class),
                "getClassLoader",
                "()Ljava/lang/ClassLoader;",
                &[],
            )?.l()?,
        )?,
    );

    FIND_CLASS_METHOD = Some(env.get_method_id(
        "java/lang/ClassLoader",
        "findClass",
        "(Ljava/lang/String;)Ljava/lang/Class;",
    )?);

    Ok(())
}

#[cfg(not(target_os = "android"))]
pub(crate) fn init_jni_logging() -> Result<(), JniError> {
    Ok(())
}

#[cfg(target_os = "android")]
pub(crate) fn init_jni_logging() -> Result<(), JniError> {
    use android_logger::Filter;
    use log::Level;

    android_logger::init_once(
        Filter::default().with_min_level(Level::Info),
        Some("safe_app_jni"),
    );

    Ok(())
}

/// Find a class on desktop JNI.
#[cfg(not(target_os = "android"))]
pub(crate) unsafe fn find_class<'a>(
    env: &'a JNIEnv,
    class_name: &str,
) -> Result<AutoLocal<'a>, JniError> {
    Ok(env.auto_local(*env.find_class(class_name)?))
}

/// Use the cached class loader to find a Java class on Android.
#[cfg(target_os = "android")]
pub(crate) unsafe fn find_class<'a>(
    env: &'a JNIEnv,
    class_name: &str,
) -> Result<AutoLocal<'a>, JniError> {
    let cls = env.auto_local(*env.new_string(class_name)?);

    Ok(env.auto_local(From::from(
        env.call_method_unsafe(
            CLASS_LOADER
                .as_ref()
                .ok_or_else(|| JniError::from("Unexpected - no cached class loader"))?
                .as_obj(),
            FIND_CLASS_METHOD
                .ok_or_else(|| JniError::from("Unexpected - no cached findClass method ID"))?,
            JavaType::from_str("Ljava/lang/Object;")?,
            &[JValue::from(cls.as_obj())],
        )?.l()?,
    )))
}

// Trait for conversion of rust value to java value.
trait ToJava<'a, T: Sized + 'a> {
    fn to_java(&self, env: &'a JNIEnv) -> JniResult<T>;
}

// Trait for conversion of java value to rust value.
trait FromJava<T> {
    fn from_java(env: &JNIEnv, input: T) -> JniResult<Self>
    where
        Self: Sized;
}

gen_primitive_type_converter!(u8, jbyte);
gen_primitive_type_converter!(i32, jint);
gen_primitive_type_converter!(u32, jint);
gen_primitive_type_converter!(i64, jlong);
gen_primitive_type_converter!(u64, jlong);

gen_byte_array_converter!(i8, 8);
gen_byte_array_converter!(u8, 24);
gen_byte_array_converter!(u8, 32);
gen_byte_array_converter!(u8, 64);

impl<'a> ToJava<'a, bool> for bool {
    fn to_java(&self, _env: &JNIEnv) -> JniResult<bool> {
        Ok(*self)
    }
}

impl<'a> ToJava<'a, jlong> for usize {
    fn to_java(&self, _env: &JNIEnv) -> JniResult<jlong> {
        Ok(*self as jlong)
    }
}

impl<'a> FromJava<JString<'a>> for *const c_char {
    fn from_java(env: &JNIEnv, input: JString) -> JniResult<Self> {
        Ok(CString::from_java(env, input)?.into_raw())
    }
}

impl<'a> ToJava<'a, JString<'a>> for *const c_char {
    fn to_java(&self, env: &'a JNIEnv) -> JniResult<JString<'a>> {
        Ok(unsafe { unwrap!(env.new_string(JNIStr::from_ptr(*self).to_owned())) })
    }
}

impl<'a> FromJava<JString<'a>> for *mut c_char {
    fn from_java(env: &JNIEnv, input: JString) -> JniResult<Self> {
        Ok(<*const _>::from_java(env, input)? as *mut _)
    }
}

impl<'a> ToJava<'a, JString<'a>> for *mut c_char {
    fn to_java(&self, env: &'a JNIEnv) -> JniResult<JString<'a>> {
        Ok((*self as *const c_char).to_java(env)?)
    }
}

impl<'a> FromJava<JString<'a>> for CString {
    fn from_java(env: &JNIEnv, input: JString) -> JniResult<Self> {
        let tmp: &CStr = &*unwrap!(env.get_string(input));
        Ok(tmp.to_owned())
    }
}

// TODO: implement this for all primitive types (consider defining a `PrimitiveType`
// trait and implement it for all rust types that correspond to primitive java types)
impl<'a, 'b> ToJava<'a, JObject<'a>> for &'b [i32] {
    fn to_java(&self, env: &'a JNIEnv) -> JniResult<JObject<'a>> {
        let output = env.new_int_array(self.len() as jsize)?;
        env.set_int_array_region(output, 0, self)?;
        Ok(JObject::from(output as jobject))
    }
}

impl<'a, 'b> ToJava<'a, JObject<'a>> for &'b [u8] {
    fn to_java(&self, env: &'a JNIEnv) -> JniResult<JObject<'a>> {
        let output = env.new_byte_array(self.len() as jsize)?;
        env.set_byte_array_region(output, 0, unsafe {
            slice::from_raw_parts(self.as_ptr() as *const i8, self.len())
        })?;
        Ok(JObject::from(output as jobject))
    }
}

impl<'a> FromJava<JObject<'a>> for Vec<u8> {
    fn from_java(env: &JNIEnv, input: JObject) -> JniResult<Self> {
        let input = input.into_inner() as jbyteArray;
        Ok(env.convert_byte_array(input)?)
    }
}

gen_object_array_converter!(
    find_class,
    RegisteredApp,
    "net/maidsafe/safe_authenticator/RegisteredApp"
);
gen_object_array_converter!(
    find_class,
    AppAccess,
    "net/maidsafe/safe_authenticator/AppAccess"
);
gen_object_array_converter!(
    find_class,
    AppExchangeInfo,
    "net/maidsafe/safe_authenticator/AppExchangeInfo"
);
gen_object_array_converter!(
    find_class,
    MDataKey,
    "net/maidsafe/safe_authenticator/MDataKey"
);
gen_object_array_converter!(
    find_class,
    MDataValue,
    "net/maidsafe/safe_authenticator/MDataValue"
);
gen_object_array_converter!(
    find_class,
    MDataEntry,
    "net/maidsafe/safe_authenticator/MDataEntry"
);
gen_object_array_converter!(
    find_class,
    ContainerPermissions,
    "net/maidsafe/safe_authenticator/ContainerPermissions"
);
gen_object_array_converter!(
    find_class,
    MetadataResponse,
    "net/maidsafe/safe_authenticator/MetadataResponse"
);

extern "C" fn call_auth_disconnect_cb(ctx: *mut c_void) {
    unsafe {
        let guard = jni_unwrap!(EnvGuard::new(JVM.as_ref()));
        let env = guard.env();
        let mut cbs = Box::from_raw(ctx as *mut [Option<GlobalRef>; 2usize]);
        if let Some(ref cb) = cbs[0usize] {
            jni_unwrap!(env.call_method(cb.as_obj(), "call", "()V", &[]));
        }
        mem::forget(cbs);
    }
}

extern "C" fn call_create_acc_cb(
    ctx: *mut c_void,
    result: *const FfiResult,
    authenticator: *mut Authenticator,
) {
    unsafe {
        let guard = jni_unwrap!(EnvGuard::new(JVM.as_ref()));
        let env = guard.env();
        let mut cbs = Box::from_raw(ctx as *mut [Option<GlobalRef>; 2usize]);
        if let Some(cb) = cbs[1usize].take() {
            let result = if result.is_null() {
                JObject::null()
            } else {
                jni_unwrap!((*result).to_java(&env))
            };
            let authenticator = authenticator as jlong;
            jni_unwrap!(env.call_method(
                cb.as_obj(),
                "call",
                "(Lnet/maidsafe/safe_authenticator/FfiResult;J)V",
                &[result.into(), authenticator.into()],
            ));
        }
        // do not drop the disconnect_notifier_cb
        mem::forget(cbs);
    }
}

#[link(name = "safe_authenticator")]
extern "C" {
    fn create_acc(
        account_locator: *const c_char,
        account_password: *const c_char,
        invitation: *const c_char,
        user_data: *mut c_void,
        o_disconnect_notifier_cb: extern "C" fn(user_data: *mut c_void),
        o_cb: extern "C" fn(
            user_data: *mut c_void,
            result: *const FfiResult,
            authenticator: *mut Authenticator,
        ),
    );
}

#[no_mangle]
pub unsafe extern "system" fn Java_net_maidsafe_safe_1authenticator_NativeBindings_createAcc(
    env: JNIEnv,
    _class: JClass,
    account_locator: JString,
    account_password: JString,
    invitation: JString,
    o_disconnect_notifier_cb: JObject,
    o_cb: JObject,
) {
    let account_locator = jni_unwrap!(CString::from_java(&env, account_locator));
    let account_password = jni_unwrap!(CString::from_java(&env, account_password));
    let invitation = jni_unwrap!(CString::from_java(&env, invitation));
    let ctx = gen_ctx!(env, o_disconnect_notifier_cb, o_cb);

    create_acc(
        account_locator.as_ptr(),
        account_password.as_ptr(),
        invitation.as_ptr(),
        ctx,
        call_auth_disconnect_cb,
        call_create_acc_cb,
    );
}

extern "C" fn call_login_cb(
    ctx: *mut c_void,
    result: *const FfiResult,
    authenticaor: *mut Authenticator,
) {
    unsafe {
        let guard = jni_unwrap!(EnvGuard::new(JVM.as_ref()));
        let env = guard.env();
        let mut cbs = Box::from_raw(ctx as *mut [Option<GlobalRef>; 2usize]);
        if let Some(cb) = cbs[1usize].take() {
            let result = if result.is_null() {
                JObject::null()
            } else {
                jni_unwrap!((*result).to_java(&env))
            };
            let authenticaor = authenticaor as jlong;
            jni_unwrap!(env.call_method(
                cb.as_obj(),
                "call",
                "(Lnet/maidsafe/safe_authenticator/FfiResult;J)V",
                &[result.into(), authenticaor.into()],
            ));
        }
        // do not drop the disconnect_notifier_cb
        mem::forget(cbs);
    }
}

#[link(name = "safe_authenticator")]
extern "C" {
    fn login(
        account_locator: *const c_char,
        account_password: *const c_char,
        user_data: *mut c_void,
        o_disconnect_notifier_cb: unsafe extern "C" fn(user_data: *mut c_void),
        o_cb: extern "C" fn(
            user_data: *mut c_void,
            result: *const FfiResult,
            authenticaor: *mut Authenticator,
        ),
    );
}

#[no_mangle]
pub unsafe extern "system" fn Java_net_maidsafe_safe_1authenticator_NativeBindings_login(
    env: JNIEnv,
    _class: JClass,
    account_locator: JString,
    account_password: JString,
    o_disconnect_notifier_cb: JObject,
    o_cb: JObject,
) {
    let account_locator = jni_unwrap!(CString::from_java(&env, account_locator));
    let account_password = jni_unwrap!(CString::from_java(&env, account_password));
    let ctx = gen_ctx!(env, o_disconnect_notifier_cb, o_cb);
    login(
        account_locator.as_ptr(),
        account_password.as_ptr(),
        ctx,
        call_auth_disconnect_cb,
        call_login_cb,
    );
}

// Include automatically generated bindings
include!("../../bindings/java/safe_authenticator/jni.rs");
