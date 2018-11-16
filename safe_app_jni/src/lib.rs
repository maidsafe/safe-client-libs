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
extern crate safe_app;
extern crate safe_core;
#[macro_use]
extern crate unwrap;

use ffi_utils::java::{convert_cb_from_java, object_array_to_java, EnvGuard, JniResult};
use ffi_utils::*;
use jni::errors::{Error as JniError, ErrorKind};
use jni::objects::{AutoLocal, GlobalRef, JClass, JMethodID, JObject, JString, JValue};
use jni::strings::JNIStr;
use jni::sys::{jbyte, jbyteArray, jclass, jint, jlong, jobject, jsize};
use jni::{signature::JavaType, AttachGuard, JNIEnv, JavaVM};
use safe_app::ffi::object_cache::*;
use safe_app::UserPermissionSet;
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
struct App(*mut c_void);

pub type SEWriterHandle = SelfEncryptorWriterHandle;
pub type SEReaderHandle = SelfEncryptorReaderHandle;

static mut JVM: Option<JavaVM> = None;
static mut CLASS_LOADER: Option<GlobalRef> = None;
static mut FIND_CLASS_METHOD: Option<JMethodID> = None;

/// Trait for conversion of Rust value to Java value.
pub trait ToJava<'a, T: Sized + 'a> {
    /// Converts Rust value to Java value
    fn to_java(&self, env: &'a JNIEnv) -> JniResult<T>;
}

/// Trait for conversion of Java value to Rust value.
pub trait FromJava<T> {
    /// Converts Java value to Rust value
    fn from_java(env: &JNIEnv, input: T) -> JniResult<Self>
    where
        Self: Sized;
}

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

    let res_class = env.find_class("net/maidsafe/safe_app/FfiResult")?;

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

gen_object_array_converter!(find_class, MDataKey, "net/maidsafe/safe_app/MDataKey");
gen_object_array_converter!(find_class, MDataValue, "net/maidsafe/safe_app/MDataValue");
gen_object_array_converter!(
    find_class,
    UserPermissionSet,
    "net/maidsafe/safe_app/UserPermissionSet"
);
gen_object_array_converter!(find_class, MDataEntry, "net/maidsafe/safe_app/MDataEntry");
gen_object_array_converter!(
    find_class,
    ContainerPermissions,
    "net/maidsafe/safe_app/ContainerPermissions"
);

extern "C" fn call_app_disconnect_cb(ctx: *mut c_void) {
    unsafe {
        let guard = jni_unwrap!(EnvGuard::new(JVM.as_ref()));
        let env = guard.env();
        let mut cbs = Box::from_raw(ctx as *mut [Option<GlobalRef>; 2usize]);
        if let Some(ref cb) = cbs[0usize] {
            jni_unwrap!(env.call_method(cb.as_obj(), "call", "()V", &[]));
        }
        // do not drop the disconnect_notifier_cb
        mem::forget(cbs);
    }
}
extern "C" fn call_app_unregistered_cb(ctx: *mut c_void, result: *const FfiResult, app: *mut App) {
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
            let app = app as jlong;
            jni_unwrap!(env.call_method(
                cb.as_obj(),
                "call",
                "(Lnet/maidsafe/safe_app/FfiResult;J)V",
                &[result.into(), app.into()],
            ));
        }
        // do not drop the disconnect_notifier_cb
        mem::forget(cbs);
    }
}

#[link(name = "safe_app")]
extern "C" {
    fn app_unregistered(
        bootstrap_config: *const u8,
        bootstrap_config_len: usize,
        user_data: *mut c_void,
        o_disconnect_notifier_cb: extern "C" fn(user_data: *mut c_void),
        o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, app: *mut App),
    );
}
#[no_mangle]
pub unsafe extern "system" fn Java_net_maidsafe_safe_1app_NativeBindings_appUnregistered(
    env: JNIEnv,
    _class: JClass,
    bootstrap_config: JObject,
    o_disconnect_notifier_cb: JObject,
    o_cb: JObject,
) {
    let bootstrap_config = jni_unwrap!(Vec::from_java(&env, bootstrap_config));
    let ctx = gen_ctx!(env, o_disconnect_notifier_cb, o_cb);
    app_unregistered(
        bootstrap_config.as_ptr(),
        bootstrap_config.len(),
        ctx,
        call_app_disconnect_cb,
        call_app_unregistered_cb,
    );
}
extern "C" fn call_app_registered_cb(ctx: *mut c_void, result: *const FfiResult, app: *mut App) {
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
            let app = app as jlong;
            jni_unwrap!(env.call_method(
                cb.as_obj(),
                "call",
                "(Lnet/maidsafe/safe_app/FfiResult;J)V",
                &[result.into(), app.into()],
            ));
        }
        // do not drop the disconnect_notifier_cb
        mem::forget(cbs);
    }
}

#[link(name = "safe_app")]
extern "C" {
    fn app_registered(
        app_id: *const c_char,
        auth_granted: *const AuthGranted,
        user_data: *mut c_void,
        o_disconnect_notifier_cb: extern "C" fn(user_data: *mut c_void),
        o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, app: *mut App),
    );
}
#[no_mangle]
pub unsafe extern "system" fn Java_net_maidsafe_safe_1app_NativeBindings_appRegistered(
    env: JNIEnv,
    _class: JClass,
    app_id: JString,
    auth_granted: JObject,
    o_disconnect_notifier_cb: JObject,
    o_cb: JObject,
) {
    let app_id = jni_unwrap!(CString::from_java(&env, app_id));
    let auth_granted = jni_unwrap!(AuthGranted::from_java(&env, auth_granted));
    let ctx = gen_ctx!(env, o_disconnect_notifier_cb, o_cb);
    app_registered(
        app_id.as_ptr(),
        &auth_granted,
        ctx,
        call_app_disconnect_cb,
        call_app_registered_cb,
    );
}

// Include automatically generated bindings
include!("../../bindings/java/safe_app/jni.rs");
