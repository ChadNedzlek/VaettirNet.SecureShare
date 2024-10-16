using System;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare;

public interface ISignable<TSelf> : IBinarySerializable<TSelf> where TSelf : IBinarySerializable<TSelf>
{
    Guid Authorizer { get; }
}