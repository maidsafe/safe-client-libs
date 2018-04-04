#if !NETSTANDARD1_2 || __DESKTOP__

using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using SafeAuth.Utilities;

#if __IOS__
using ObjCRuntime;
#endif

namespace SafeAuth.AuthBindings {
  internal partial class AuthBindings {
    public void CreateAccount(
      string locator,
      string secret,
      string invitation,
      Action disconnnectedCb,
      Action<FfiResult, IntPtr, GCHandle> cb) {
      var userData = BindingUtils.ToHandlePtr((disconnnectedCb, cb));
      CreateAccNative(locator, secret, invitation, userData, OnAuthenticatorDisconnectCb, OnAuthenticatorCreateCb);
    }

    public Task<IpcReq> DecodeIpcMessage(IntPtr authPtr, string msg) {
      var (task, userData) = BindingUtils.PrepareTask<IpcReq>();
      AuthDecodeIpcMsgNative(
        authPtr,
        msg,
        userData,
        OnDecodeIpcReqAuthCb,
        OnDecodeIpcReqContainersCb,
        OnDecodeIpcReqUnregisteredCb,
        OnDecodeIpcReqShareMDataCb,
        OnFfiResultIpcReqErrorCb);
      return task;
    }

    public void Login(string locator, string secret, Action disconnnectedCb, Action<FfiResult, IntPtr, GCHandle> cb) {
      var userData = BindingUtils.ToHandlePtr((disconnnectedCb, cb));
      LoginNative(locator, secret, userData, OnAuthenticatorDisconnectCb, OnAuthenticatorCreateCb);
    }

    public Task<IpcReq> UnRegisteredDecodeIpcMsgAsync(string msg) {
      var (task, userData) = BindingUtils.PrepareTask<IpcReq>();
      AuthUnregisteredDecodeIpcMsgNative(msg, userData, OnDecodeIpcReqUnregisteredCb, OnFfiResultIpcReqErrorCb);
      return task;
    }

#if __IOS__
    [MonoPInvokeCallback(typeof(FfiResultAuthenticatorCb))]
#endif
    private static void OnAuthenticatorCreateCb(IntPtr userData, IntPtr result, IntPtr app) {
      var (_, action) = BindingUtils.FromHandlePtr<(Action, Action<FfiResult, IntPtr, GCHandle>)>(userData, false);

      action(Marshal.PtrToStructure<FfiResult>(result), app, GCHandle.FromIntPtr(userData));
    }
#if __IOS__
    [MonoPInvokeCallback(typeof(NoneCb))]
#endif
    private static void OnAuthenticatorDisconnectCb(IntPtr userData) {
      var (action, _) = BindingUtils.FromHandlePtr<(Action, Action<FfiResult, IntPtr, GCHandle>)>(userData, false);

      action();
    }

#if __IOS__
    [MonoPInvokeCallback(typeof(UIntAuthReqCb))]
#endif
    private static void OnDecodeIpcReqAuthCb(IntPtr userData, uint reqId, IntPtr authReq) {
      var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcReq>>(userData);
      tcs.SetResult(new AuthIpcReq(reqId, new AuthReq(Marshal.PtrToStructure<AuthReqNative>(authReq))));
    }

#if __IOS__
    [MonoPInvokeCallback(typeof(UIntContainersReqCb))]
#endif
    private static void OnDecodeIpcReqContainersCb(IntPtr userData, uint reqId, IntPtr authReq) {
      var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcReq>>(userData);
      tcs.SetResult(new ContainersIpcReq(reqId, new ContainersReq(Marshal.PtrToStructure<ContainersReqNative>(authReq))));
    }

#if __IOS__
    [MonoPInvokeCallback(typeof(UIntShareMDataReqMetadataResponseCb))]
#endif
    private static void OnDecodeIpcReqShareMDataCb(IntPtr userData, uint reqId, IntPtr authReq, IntPtr metadata) {
      var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcReq>>(userData);
      var shareMdReq = new ShareMDataReq(Marshal.PtrToStructure<ShareMDataReqNative>(authReq));
      var metadataResponse = Marshal.PtrToStructure<MetadataResponse>(metadata);
      tcs.SetResult(new ShareMDataIpcReq(reqId, shareMdReq, metadataResponse));
    }

#if __IOS__
    [MonoPInvokeCallback(typeof(UIntByteListCb))]
#endif
    private static void OnDecodeIpcReqUnregisteredCb(IntPtr userData, uint reqId, IntPtr extraData, UIntPtr size) {
      var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcReq>>(userData);
      tcs.SetResult(new UnregisteredIpcReq(reqId, extraData, (ulong)size));
    }

#if __IOS__
    [MonoPInvokeCallback(typeof(FfiResultIpcReqErrorCb))]
#endif
    private static void OnFfiResultIpcReqErrorCb(IntPtr userData, IntPtr result, string msg) {
      var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcReq>>(userData);
      var ffiResult = Marshal.PtrToStructure<FfiResult>(result);
      tcs.SetResult(new IpcReqError(ffiResult.ErrorCode, ffiResult.Description, msg));
    }

    // ReSharper disable once UnusedMember.Local
    private delegate void FfiResultIpcReqErrorCb(IntPtr userData, IntPtr result, string msg);
  }
}
#endif