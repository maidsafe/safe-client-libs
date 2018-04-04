using System;
using System.Collections.Generic;
using JetBrains.Annotations;

namespace SafeApp.Utilities {
  [PublicAPI]
  public abstract class IpcMsg {
  }

  [PublicAPI]
  public class AuthIpcMsg : IpcMsg {
    public uint ReqId;
    public AuthGranted AuthGranted;

    public AuthIpcMsg(uint reqId, AuthGranted authGranted) {
        ReqId = reqId;
        AuthGranted = authGranted;
    }
  }

  [PublicAPI]
  public class UnregisteredIpcMsg : IpcMsg {
    public uint ReqId;
    public List<byte> SerialisedCfg;

    public UnregisteredIpcMsg(uint reqId, IntPtr serialisedCfgPtr, UIntPtr serialisedCfgLen) {
        ReqId = reqId;
        SerialisedCfg = BindingUtils.CopyToByteList(serialisedCfgPtr, (int) serialisedCfgLen);
    }
  }

  [PublicAPI]
  public class ContainersIpcMsg : IpcMsg {
    public uint ReqId;

    public ContainersIpcMsg(uint reqId) {
        ReqId = reqId;
    }
  }

  [PublicAPI]
  public class ShareMDataIpcMsg : IpcMsg {
    public uint ReqId;

    public ShareMDataIpcMsg(uint reqId) {
        ReqId = reqId;
    }
  }

  [PublicAPI]
  public class RevokedIpcMsg : IpcMsg {

  }

  [PublicAPI]
  public class IpcMsgException : FfiException {
    public readonly uint ReqId;

    public IpcMsgException(uint reqId, int code, string description)
        : base(code, description)
    {
        ReqId = reqId;
    }
  }
}
