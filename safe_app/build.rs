// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Build script for generating C header files from FFI modules.

extern crate ffi_utils;
extern crate jni;
extern crate routing;
extern crate rust_sodium;
extern crate safe_bindgen;
#[macro_use]
extern crate unwrap;

use jni::signature::{JavaType, Primitive};
use routing::XOR_NAME_LEN;
use rust_sodium::crypto::{box_, secretbox, sign};
use safe_bindgen::{Bindgen, FilterMode, LangC, LangCSharp, LangJava};
use std::collections::HashMap;
use std::env;
use std::path::Path;

const BSD_MIT_LICENSE: &str =
    "// Copyright 2018 MaidSafe.net limited.\n\
     //\n\
     // This SAFE Network Software is licensed to you under the MIT license\n\
     // <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified\n\
     // BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,\n\
     // at your option. This file may not be copied, modified, or distributed\n\
     // except according to those terms. Please review the Licences for the\n\
     // specific language governing permissions and limitations relating to use\n\
     // of the SAFE Network Software.";

// As currently we have no easy way to pull code for external dependencies for bindgen parsing,
// we use this workaround to cater for structures defined in the `ffi_utils` package. At present,
// it's only `FfiResult`.
const FFI_UTILS_CODE: &str =
    "#[repr(C)] pub struct FfiResult { error_code: i32, description: *const c_char }";

fn main() {
    if env::var("CARGO_FEATURE_BINDINGS").is_err() {
        return;
    }

    gen_bindings_c();
    gen_bindings_csharp();
    gen_bindings_java();
}

fn gen_bindings_c() {
    let target_dir = Path::new("../bindings/c/safe_app");
    let mut outputs = HashMap::new();

    let mut bindgen = unwrap!(Bindgen::new());
    let mut lang = LangC::new();

    lang.set_lib_name("ffi_utils");
    bindgen.source_code("ffi_utils/src/lib.rs", FFI_UTILS_CODE);
    unwrap!(bindgen.compile(&mut lang, &mut outputs, false));

    lang.set_lib_name("safe_core");
    bindgen.source_file("../safe_core/src/lib.rs");
    unwrap!(bindgen.compile(&mut lang, &mut outputs, false));

    lang.add_custom_code("typedef void* App;\n");
    lang.set_lib_name(unwrap!(env::var("CARGO_PKG_NAME")));
    bindgen.source_file("../safe_app/src/lib.rs");
    unwrap!(bindgen.compile(&mut lang, &mut outputs, true));

    add_license_headers(&mut outputs);
    unwrap!(bindgen.write_outputs(target_dir, &outputs));
}

fn gen_bindings_java() {
    let target_dir = Path::new("../bindings/java/safe_app");

    let mut type_map = HashMap::new();
    type_map.insert(
        "XorNameArray",
        JavaType::Array(Box::new(JavaType::Primitive(Primitive::Byte))),
    );
    type_map.insert(
        "SignSecretKey",
        JavaType::Array(Box::new(JavaType::Primitive(Primitive::Byte))),
    );
    type_map.insert(
        "SignPublicKey",
        JavaType::Array(Box::new(JavaType::Primitive(Primitive::Byte))),
    );
    type_map.insert(
        "SymSecretKey",
        JavaType::Array(Box::new(JavaType::Primitive(Primitive::Byte))),
    );
    type_map.insert(
        "SymNonce",
        JavaType::Array(Box::new(JavaType::Primitive(Primitive::Byte))),
    );
    type_map.insert(
        "AsymPublicKey",
        JavaType::Array(Box::new(JavaType::Primitive(Primitive::Byte))),
    );
    type_map.insert(
        "AsymSecretKey",
        JavaType::Array(Box::new(JavaType::Primitive(Primitive::Byte))),
    );
    type_map.insert(
        "AsymNonce",
        JavaType::Array(Box::new(JavaType::Primitive(Primitive::Byte))),
    );
    type_map.insert("CipherOptHandle", JavaType::Primitive(Primitive::Long));
    type_map.insert("EncryptPubKeyHandle", JavaType::Primitive(Primitive::Long));
    type_map.insert("EncryptSecKeyHandle", JavaType::Primitive(Primitive::Long));
    type_map.insert("MDataEntriesHandle", JavaType::Primitive(Primitive::Long));
    type_map.insert(
        "MDataEntryActionsHandle",
        JavaType::Primitive(Primitive::Long),
    );
    type_map.insert(
        "MDataPermissionsHandle",
        JavaType::Primitive(Primitive::Long),
    );
    type_map.insert(
        "SelfEncryptorReaderHandle",
        JavaType::Primitive(Primitive::Long),
    );
    type_map.insert(
        "SelfEncryptorWriterHandle",
        JavaType::Primitive(Primitive::Long),
    );
    type_map.insert("SEReaderHandle", JavaType::Primitive(Primitive::Long));
    type_map.insert("SEWriterHandle", JavaType::Primitive(Primitive::Long));
    type_map.insert("SignPubKeyHandle", JavaType::Primitive(Primitive::Long));
    type_map.insert("SignSecKeyHandle", JavaType::Primitive(Primitive::Long));
    type_map.insert("FileContextHandle", JavaType::Primitive(Primitive::Long));
    type_map.insert("App", JavaType::Primitive(Primitive::Long));
    type_map.insert("Authenticator", JavaType::Primitive(Primitive::Long));

    let mut bindgen = unwrap!(Bindgen::new());
    let mut lang = LangJava::new(type_map);

    lang.filter("app_registered");
    lang.filter("app_unregistered");

    lang.set_namespace("net.maidsafe.safe_app");
    lang.set_model_namespace("net.maidsafe.safe_app");

    let mut outputs = HashMap::new();

    bindgen.source_file("../safe_core/src/lib.rs");
    lang.set_lib_name("safe_core");
    unwrap!(bindgen.compile(&mut lang, &mut outputs, false));

    bindgen.source_code("ffi_utils/src/lib.rs", FFI_UTILS_CODE);
    lang.set_lib_name("ffi_utils");
    unwrap!(bindgen.compile(&mut lang, &mut outputs, false));

    bindgen.source_file("src/lib.rs");
    lang.set_lib_name(unwrap!(env::var("CARGO_PKG_NAME")));
    unwrap!(bindgen.compile(&mut lang, &mut outputs, true));

    add_license_headers(&mut outputs);
    unwrap!(bindgen.write_outputs(target_dir, &outputs));
}

fn gen_bindings_csharp() {
    let target_dir = Path::new("../bindings/csharp/safe_app");
    let test_idents = ["test_create_app", "test_create_app_with_access"];

    let mut bindgen = unwrap!(Bindgen::new());
    let mut lang = LangCSharp::new();

    lang.set_lib_name(unwrap!(env::var("CARGO_PKG_NAME")));

    lang.set_interface_section(
        "SafeApp.Utilities/IAppBindings.cs",
        "SafeApp.Utilities",
        "IAppBindings",
    );
    lang.set_functions_section(
        "SafeApp.AppBindings/AppBindings.cs",
        "SafeApp.AppBindings",
        "AppBindings",
    );
    lang.set_consts_section(
        "SafeApp.Utilities/AppConstants.cs",
        "SafeApp.Utilities",
        "AppConstants",
    );
    lang.set_types_section("SafeApp.Utilities/AppTypes.cs", "SafeApp.Utilities");
    lang.set_utils_section(
        "SafeApp.Utilities/BindingUtils.cs",
        "SafeApp.Utilities",
        "BindingUtils",
    );

    lang.add_const("ulong", "ASYM_PUBLIC_KEY_LEN", box_::PUBLICKEYBYTES);
    lang.add_const("ulong", "ASYM_SECRET_KEY_LEN", box_::SECRETKEYBYTES);
    lang.add_const("ulong", "ASYM_NONCE_LEN", box_::NONCEBYTES);
    lang.add_const("ulong", "SYM_KEY_LEN", secretbox::KEYBYTES);
    lang.add_const("ulong", "SYM_NONCE_LEN", secretbox::NONCEBYTES);
    lang.add_const("ulong", "SIGN_PUBLIC_KEY_LEN", sign::PUBLICKEYBYTES);
    lang.add_const("ulong", "SIGN_SECRET_KEY_LEN", sign::SECRETKEYBYTES);
    lang.add_const("ulong", "XOR_NAME_LEN", XOR_NAME_LEN);
    lang.add_opaque_type("App");

    lang.reset_filter(FilterMode::Blacklist);
    for &ident in &test_idents {
        lang.filter(ident);
    }

    bindgen.source_file("../safe_core/src/lib.rs");
    bindgen.compile_or_panic(&mut lang, &mut HashMap::new(), false);

    let mut outputs = HashMap::new();
    bindgen.source_file("src/lib.rs");
    bindgen.compile_or_panic(&mut lang, &mut outputs, true);
    apply_patches(&mut outputs);
    bindgen.write_outputs_or_panic(target_dir, &outputs);

    // Testing utilities.
    lang.set_interface_section(
        "SafeApp.MockAuthBindings/IMockAuthBindings.cs",
        "SafeApp.MockAuthBindings",
        "IMockAuthBindings",
    );
    lang.set_functions_section(
        "SafeApp.MockAuthBindings/MockAuthBindings.cs",
        "SafeApp.MockAuthBindings",
        "MockAuthBindings",
    );

    lang.set_consts_enabled(false);
    lang.set_types_enabled(false);
    lang.set_utils_enabled(false);
    lang.add_opaque_type("App");

    lang.reset_filter(FilterMode::Whitelist);
    for &ident in &test_idents {
        lang.filter(ident);
    }

    outputs.clear();
    bindgen.compile_or_panic(&mut lang, &mut outputs, true);
    apply_patches_testing(&mut outputs);
    add_license_headers(&mut outputs);
    bindgen.write_outputs_or_panic(target_dir, &outputs);

    // Hand-written code.
    unwrap!(ffi_utils::bindgen_utils::copy_files(
        "resources",
        target_dir,
        ".cs",
    ));
}

fn add_license_headers(outputs: &mut HashMap<String, String>) {
    for content in outputs.values_mut() {
        add_license_header(content);
    }
}

fn add_license_header(content: &mut String) {
    *content = format!("{}\n{}", BSD_MIT_LICENSE, content);
}

fn apply_patches(outputs: &mut HashMap<String, String>) {
    {
        let content = fetch_mut(outputs, "SafeApp.AppBindings/AppBindings.cs");
        insert_using_utilities(content);
        insert_using_obj_c_runtime(content);
        insert_guard(content);
        insert_resharper_disable_inconsistent_naming(content);
    }

    insert_internals_visible_to(fetch_mut(outputs, "SafeApp.Utilities/AppTypes.cs"));

    for content in outputs.values_mut() {
        fix_names(content);
    }
}

fn apply_patches_testing(outputs: &mut HashMap<String, String>) {
    insert_using_utilities(fetch_mut(
        outputs,
        "SafeApp.MockAuthBindings/MockAuthBindings.cs",
    ));

    insert_using_utilities(fetch_mut(
        outputs,
        "SafeApp.MockAuthBindings/IMockAuthBindings.cs",
    ));

    for content in outputs.values_mut() {
        fix_names(content);
    }
}

fn insert_guard(content: &mut String) {
    content.insert_str(0, "#if !NETSTANDARD1_2 || __DESKTOP__\n");
    content.push_str("#endif\n");
}

fn insert_using_utilities(content: &mut String) {
    content.insert_str(0, "using SafeApp.Utilities;\n");
}

fn insert_using_obj_c_runtime(content: &mut String) {
    content.insert_str(0, "#if __IOS__\nusing ObjCRuntime;\n#endif\n");
}

fn insert_internals_visible_to(content: &mut String) {
    content.insert_str(0, "using System.Runtime.CompilerServices;\n");

    // HACK: The [assembly: ...] annotation must go after all using declaration.
    *content = content.replace(
        "namespace SafeApp.Utilities",
        "[assembly: InternalsVisibleTo(\"SafeApp.AppBindings\")]\n\
         [assembly: InternalsVisibleTo(\"SafeApp.MockAuthBindings\")]\n\n\
         namespace SafeApp.Utilities",
    );
}

fn insert_resharper_disable_inconsistent_naming(content: &mut String) {
    content.insert_str(0, "// ReSharper disable InconsistentNaming\n");
}

fn fix_names(content: &mut String) {
    *content = content.replace("Idata", "IData").replace("Mdata", "MData");
}

fn fetch_mut<'a>(outputs: &'a mut HashMap<String, String>, key: &str) -> &'a mut String {
    unwrap!(outputs.get_mut(key), "key {:?} not found in outputs", key)
}
