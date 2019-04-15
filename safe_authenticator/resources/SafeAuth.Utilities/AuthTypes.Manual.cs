using System;
using System.Collections.Generic;
using JetBrains.Annotations;

namespace SafeAuth.Utilities
{
#pragma warning disable SA1401 // Fields should be private
    public abstract class IpcReq
    {
    }

    [PublicAPI]
    public class AuthIpcReq : IpcReq
    {
        public AuthReq AuthReq;
        public uint ReqId;

        public AuthIpcReq(uint reqId, AuthReq authReq)
        {
            ReqId = reqId;
            AuthReq = authReq;
        }
    }

    [PublicAPI]
    public class UnregisteredIpcReq : IpcReq
    {
        public List<byte> ExtraData;
        public uint ReqId;

        public UnregisteredIpcReq(uint reqId, IntPtr extraDataPtr, ulong extraDataLength)
        {
            ReqId = reqId;
            ExtraData = BindingUtils.CopyToByteList(extraDataPtr, (int)extraDataLength);
        }
    }

    [PublicAPI]
    public class ContainersIpcReq : IpcReq
    {
        public ContainersReq ContainersReq;
        public uint ReqId;

        public ContainersIpcReq(uint reqId, ContainersReq containersReq)
        {
            ReqId = reqId;
            ContainersReq = containersReq;
        }
    }

    [PublicAPI]
    public class ShareMDataIpcReq : IpcReq
    {
        public List<MetadataResponse> MetadataResponse;
        public uint ReqId;
        public ShareMDataReq ShareMDataReq;

        public ShareMDataIpcReq(uint reqId, ShareMDataReq shareMDataReq, List<MetadataResponse> metadataResponseList)
        {
            ReqId = reqId;
            ShareMDataReq = shareMDataReq;
            MetadataResponse = metadataResponseList;
        }
    }

    [PublicAPI]
    public class IpcReqRejected : IpcReq
    {
        public readonly string Msg;

        public IpcReqRejected(string msg)
        {
            Msg = msg;
        }
    }

    [PublicAPI]
    public class IpcReqError : IpcReq
    {
        public readonly int Code;
        public readonly string Description;
        public readonly string Msg;

        public IpcReqError(int code, string description, string msg)
        {
            Code = code;
            Description = description;
            Msg = msg;
        }
    }
#pragma warning restore SA1401 // Fields should be private
}
