use crate::apps::RegisteredApp;
use crate::ffi::apps::AppPermissions;
use ffi_utils::{vec_into_raw_parts, ReprC};
use safe_authenticator::apps::RegisteredApp as NativeRegisteredApp;
use safe_core::ipc::req::{containers_from_repr_c, containers_into_vec};
use safe_core::ipc::AppExchangeInfo as NativeAppExchangeInfo;
use safe_core::ipc::IpcError;
use safe_nd::AppPermissions as NativeAppPermissions;

#[allow(unsafe_code)]
pub unsafe fn registered_app_into_repr_c(
    app: &NativeRegisteredApp,
) -> Result<RegisteredApp, IpcError> {
    let container_permissions_vec = containers_into_vec(app.containers.clone().into_iter())?;
    let (containers_ptr, containers_len) = vec_into_raw_parts(container_permissions_vec);
    let ffi_app_perms = AppPermissions {
        transfer_coins: app.app_perms.transfer_coins,
        get_balance: app.app_perms.get_balance,
        perform_mutations: app.app_perms.perform_mutations,
    };

    Ok(RegisteredApp {
        app_info: app.app_info.clone().into_repr_c()?,
        containers: containers_ptr,
        containers_len,
        app_permissions: ffi_app_perms,
    })
}

#[allow(unsafe_code)]
pub unsafe fn native_registered_app_into_native(
    app: &RegisteredApp,
) -> Result<NativeRegisteredApp, IpcError> {
    let native_app_perms = NativeAppPermissions {
        transfer_coins: app.app_permissions.transfer_coins,
        get_balance: app.app_permissions.get_balance,
        perform_mutations: app.app_permissions.perform_mutations,
    };

    Ok(NativeRegisteredApp {
        app_info: NativeAppExchangeInfo::clone_from_repr_c(&app.app_info)?,
        containers: containers_from_repr_c(app.containers, app.containers_len)?,
        app_perms: native_app_perms,
    })
}
