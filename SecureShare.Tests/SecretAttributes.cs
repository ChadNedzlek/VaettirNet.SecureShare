using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace SecureShare.Tests;

[ProtoContract]
public class SecretAttributes : FullSerializable<SecretAttributes>
{
    [ProtoMember(1)]
    public string Value { get; set; }
    
    public static implicit operator SecretAttributes(string value) => new() { Value = value };
}