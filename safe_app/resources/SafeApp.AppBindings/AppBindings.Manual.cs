#if !NETSTANDARD1_2 || __DESKTOP__

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using SafeApp.Utilities;

#if __IOS__
using ObjCRuntime;
#endif

namespace SafeApp.AppBindings {
  internal partial class AppBindings {
    public void AppUnregistered(List<byte> bootstrapConfig, Action oDisconnectNotifierCb, Action<FfiResult, IntPtr, GCHandle> oCb)
    {
      var userData = BindingUtils.ToHandlePtr((oDisconnectNotifierCb, oCb));

      AppUnregisteredNative(bootstrapConfig.ToArray(),
                            (UIntPtr) bootstrapConfig.Count,
                            userData,
                            OnAppDisconnectCb,
                            OnAppCreateCb);
    }

    public void AppRegistered(string appId,
                              ref AuthGranted authGranted,
                              Action oDisconnectNotifierCb,
                              Action<FfiResult, IntPtr, GCHandle> oCb)
    {
      var authGrantedNative = authGranted.ToNative();
      var userData = BindingUtils.ToHandlePtr((oDisconnectNotifierCb, oCb));

      AppRegisteredNative(appId,
                          ref authGrantedNative,
                          userData,
                          OnAppDisconnectCb,
                          OnAppCreateCb);

      authGrantedNative.Free();
    }

    #if __IOS__
    [MonoPInvokeCallback(typeof(NoneCb))]
    #endif
    private static void OnAppDisconnectCb(IntPtr userData) {
      var (action, _) =
          BindingUtils.FromHandlePtr<(Action, Action<FfiResult, IntPtr, GCHandle>)>(
              userData, false
          );

      action();
    }

    #if __IOS__
    [MonoPInvokeCallback(typeof(FfiResultAppCb))]
    #endif
    private static void OnAppCreateCb(IntPtr userData, IntPtr result, IntPtr app) {
      var (_, action) =
          BindingUtils.FromHandlePtr<(Action, Action<FfiResult, IntPtr, GCHandle>)>(
              userData, false
          );

      action(Marshal.PtrToStructure<FfiResult>(result), app, GCHandle.FromIntPtr(userData));
    }

    public Task<IpcMsg> DecodeIpcMsgAsync(string msg) {
      var (task, userData) = BindingUtils.PrepareTask<IpcMsg>();
      DecodeIpcMsgNative(msg,
                         userData,
                         OnDecodeIpcMsgAuthCb,
                         OnDecodeIpcMsgUnregisteredCb,
                         OnDecodeIpcMsgContainersCb,
                         OnDecodeIpcMsgShareMdataCb,
                         OnDecodeIpcMsgRevokedCb,
                         OnDecodeIpcMsgErrCb);

      return task;
    }

    #if __IOS__
    [MonoPInvokeCallback(typeof(UIntAuthGrantedCb))]
    #endif
    private static void OnDecodeIpcMsgAuthCb(IntPtr userData, uint reqId, IntPtr authGranted)
    {
      var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcMsg>>(userData);
      tcs.SetResult(
        new AuthIpcMsg(
          reqId,
          new AuthGranted(Marshal.PtrToStructure<AuthGrantedNative>(authGranted))));
    }

    #if __IOS__
    [MonoPInvokeCallback(typeof(UIntByteListCb))]
    #endif
    private static void OnDecodeIpcMsgUnregisteredCb(IntPtr userData, uint reqId, IntPtr serialisedCfgPtr, UIntPtr serialisedCfgLen)
    {
      var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcMsg>>(userData);
      tcs.SetResult(new UnregisteredIpcMsg(reqId, serialisedCfgPtr, serialisedCfgLen));
    }

    #if __IOS__
    [MonoPInvokeCallback(typeof(UIntCb))]
    #endif
    private static void OnDecodeIpcMsgContainersCb(IntPtr userData, uint reqId)
    {
      var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcMsg>>(userData);
      tcs.SetResult(new ContainersIpcMsg(reqId));
    }

    #if __IOS__
    [MonoPInvokeCallback(typeof(UIntCb))]
    #endif
    private static void OnDecodeIpcMsgShareMdataCb(IntPtr userData, uint reqId)
    {
      var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcMsg>>(userData);
      tcs.SetResult(new ShareMDataIpcMsg(reqId));
    }

    #if __IOS__
    [MonoPInvokeCallback(typeof(NoneCb))]
    #endif
    private static void OnDecodeIpcMsgRevokedCb(IntPtr userData)
    {
      var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcMsg>>(userData);
      tcs.SetResult(new RevokedIpcMsg());
    }

    #if __IOS__
    [MonoPInvokeCallback(typeof(FfiResultUIntCb))]
    #endif
    private static void OnDecodeIpcMsgErrCb(IntPtr userData, IntPtr result, uint reqId)
    {
      var res = Marshal.PtrToStructure<FfiResult>(result);
      var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcMsg>>(userData);
      tcs.SetException(new IpcMsgException(reqId, res.ErrorCode, res.Description));
    }
  }
}
#endif