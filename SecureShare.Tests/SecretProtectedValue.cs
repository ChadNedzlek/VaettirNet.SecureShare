using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace SecureShare.Tests;

[ProtoContract]
public class SecretProtectedValue : BinarySerializable<SecretProtectedValue>
{
    [ProtoMember(1)]
    public string ProtValue { get; set; }

    public static implicit operator SecretProtectedValue(string value) => new() { ProtValue = value };
}