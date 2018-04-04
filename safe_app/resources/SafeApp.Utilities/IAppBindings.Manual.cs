using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace SafeApp.Utilities {
  public partial interface IAppBindings {
    void AppUnregistered(List<byte> bootstrapConfig, Action oDisconnectNotifierCb, Action<FfiResult, IntPtr, GCHandle> oCb);
    void AppRegistered(string appId, ref AuthGranted authGranted, Action oDisconnectNotifierCb, Action<FfiResult, IntPtr, GCHandle> oCb);
    Task<IpcMsg> DecodeIpcMsgAsync(string msg);
  }
}