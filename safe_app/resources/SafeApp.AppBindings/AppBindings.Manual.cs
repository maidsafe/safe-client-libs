#if !NETSTANDARD1_2 || __DESKTOP__

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

using SafeApp.Utilities;

#if __IOS__
using ObjCRuntime;
#endif

namespace SafeApp.AppBindings
{
    internal partial class AppBindings
    {
        public void AppUnregistered(List<byte> bootstrapConfig, Action oDisconnectNotifierCb, Action<FfiResult, IntPtr, GCHandle> oCb)
        {
            var userData = BindingUtils.ToHandlePtr((oDisconnectNotifierCb, oCb));

            AppUnregisteredNative(
              bootstrapConfig.ToArray(),
              (UIntPtr)bootstrapConfig.Count,
              userData,
              DelegateOnAppDisconnectCb,
              DelegateOnAppCreateCb);
        }

        public void AppRegistered(
          string appId,
          ref AuthGranted authGranted,
          Action oDisconnectNotifierCb,
          Action<FfiResult, IntPtr, GCHandle> oCb)
        {
            var authGrantedNative = authGranted.ToNative();
            var userData = BindingUtils.ToHandlePtr((oDisconnectNotifierCb, oCb));

            AppRegisteredNative(appId, ref authGrantedNative, userData, DelegateOnAppDisconnectCb, DelegateOnAppCreateCb);

            authGrantedNative.Free();
        }

#if __IOS__
        [MonoPInvokeCallback(typeof(NoneCb))]
#endif
        private static void OnAppDisconnectCb(IntPtr userData)
        {
            var (action, _) = BindingUtils.FromHandlePtr<(Action, Action<FfiResult, IntPtr, GCHandle>)>(userData, false);

            action();
        }

        private static readonly NoneCb DelegateOnAppDisconnectCb = OnAppDisconnectCb;

#if __IOS__
        [MonoPInvokeCallback(typeof(FfiResultAppCb))]
#endif
        private static void OnAppCreateCb(IntPtr userData, IntPtr result, IntPtr app)
        {
            var (_, action) = BindingUtils.FromHandlePtr<(Action, Action<FfiResult, IntPtr, GCHandle>)>(userData, false);

            action(Marshal.PtrToStructure<FfiResult>(result), app, GCHandle.FromIntPtr(userData));
        }

        private static readonly FfiResultAppCb DelegateOnAppCreateCb = OnAppCreateCb;

        public Task<IpcMsg> DecodeIpcMsgAsync(string msg)
        {
            var (task, userData) = BindingUtils.PrepareTask<IpcMsg>();
            DecodeIpcMsgNative(
              msg,
              userData,
              DelegateOnDecodeIpcMsgAuthCb,
              DelegateOnDecodeIpcMsgUnregisteredCb,
              DelegateOnDecodeIpcMsgContainersCb,
              DelegateOnDecodeIpcMsgShareMdataCb,
              DelegateOnDecodeIpcMsgRevokedCb,
              DelegateOnDecodeIpcMsgErrCb);

            return task;
        }

#if __IOS__
        [MonoPInvokeCallback(typeof(UIntAuthGrantedCb))]
#endif
        private static void OnDecodeIpcMsgAuthCb(IntPtr userData, uint reqId, IntPtr authGranted)
        {
            var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcMsg>>(userData);
            tcs.SetResult(new AuthIpcMsg(reqId, new AuthGranted(Marshal.PtrToStructure<AuthGrantedNative>(authGranted))));
        }

        private static readonly UIntAuthGrantedCb DelegateOnDecodeIpcMsgAuthCb = OnDecodeIpcMsgAuthCb;

#if __IOS__
        [MonoPInvokeCallback(typeof(UIntByteListCb))]
#endif
        private static void OnDecodeIpcMsgUnregisteredCb(IntPtr userData, uint reqId, IntPtr serialisedCfgPtr, UIntPtr serialisedCfgLen)
        {
            var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcMsg>>(userData);
            tcs.SetResult(new UnregisteredIpcMsg(reqId, serialisedCfgPtr, serialisedCfgLen));
        }

        private static readonly UIntByteListCb DelegateOnDecodeIpcMsgUnregisteredCb = OnDecodeIpcMsgUnregisteredCb;

#if __IOS__
        [MonoPInvokeCallback(typeof(UIntCb))]
#endif
        private static void OnDecodeIpcMsgContainersCb(IntPtr userData, uint reqId)
        {
            var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcMsg>>(userData);
            tcs.SetResult(new ContainersIpcMsg(reqId));
        }

        private static readonly UIntCb DelegateOnDecodeIpcMsgContainersCb = OnDecodeIpcMsgContainersCb;

#if __IOS__
        [MonoPInvokeCallback(typeof(UIntCb))]
#endif
        private static void OnDecodeIpcMsgShareMdataCb(IntPtr userData, uint reqId)
        {
            var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcMsg>>(userData);
            tcs.SetResult(new ShareMDataIpcMsg(reqId));
        }

        private static readonly UIntCb DelegateOnDecodeIpcMsgShareMdataCb = OnDecodeIpcMsgShareMdataCb;

#if __IOS__
        [MonoPInvokeCallback(typeof(NoneCb))]
#endif
        private static void OnDecodeIpcMsgRevokedCb(IntPtr userData)
        {
            var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcMsg>>(userData);
            tcs.SetResult(new RevokedIpcMsg());
        }

        private static readonly NoneCb DelegateOnDecodeIpcMsgRevokedCb = OnDecodeIpcMsgRevokedCb;

#if __IOS__
        [MonoPInvokeCallback(typeof(FfiResultUIntCb))]
#endif
        private static void OnDecodeIpcMsgErrCb(IntPtr userData, IntPtr result, uint reqId)
        {
            var res = Marshal.PtrToStructure<FfiResult>(result);
            var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcMsg>>(userData);
            tcs.SetException(new IpcMsgException(reqId, res.ErrorCode, res.Description));
        }

        private static readonly FfiResultUIntCb DelegateOnDecodeIpcMsgErrCb = OnDecodeIpcMsgErrCb;
    }
}
#endif
