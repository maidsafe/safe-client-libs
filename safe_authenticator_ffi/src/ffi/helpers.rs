// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::apps::RegisteredApp;
use crate::ffi::apps::AppPermissions;
use ffi_utils::{vec_into_raw_parts, ReprC};
use safe_authenticator::apps::RegisteredApp as NativeRegisteredApp;
use safe_core::ipc::req::{containers_from_repr_c, containers_into_vec};
use safe_core::ipc::AppExchangeInfo as NativeAppExchangeInfo;
use safe_core::ipc::IpcError;
use safe_nd::AppPermissions as NativeAppPermissions;

/// Registered native app converter.
pub unsafe fn registered_app_into_repr_c(
    app: &NativeRegisteredApp,
) -> Result<RegisteredApp, IpcError> {
    let container_permissions_vec = containers_into_vec(app.containers.clone().into_iter())?;
    let (containers_ptr, containers_len) = vec_into_raw_parts(container_permissions_vec);
    let ffi_app_perms = AppPermissions {
        transfer_money: app.app_perms.transfer_money,
        read_balance: app.app_perms.read_balance,
        read_transfer_history: app.app_perms.read_transfer_history,
        data_mutations: app.app_perms.data_mutations,
    };

    Ok(RegisteredApp {
        app_info: app.app_info.clone().into_repr_c()?,
        containers: containers_ptr,
        containers_len,
        app_permissions: ffi_app_perms,
    })
}

/// Convert FFI registered app into native struct.
pub unsafe fn native_registered_app_into_native(
    app: &RegisteredApp,
) -> Result<NativeRegisteredApp, IpcError> {
    let native_app_perms = NativeAppPermissions {
        transfer_money: app.app_permissions.transfer_money,
        read_balance: app.app_permissions.read_balance,
        read_transfer_history: app.app_permissions.read_transfer_history,
        data_mutations: app.app_permissions.data_mutations,
    };

    Ok(NativeRegisteredApp {
        app_info: NativeAppExchangeInfo::clone_from_repr_c(&app.app_info)?,
        containers: containers_from_repr_c(app.containers, app.containers_len)?,
        app_perms: native_app_perms,
    })
}
