using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Tests;

[PackedBinarySerializable]
public class SecretAttributes : FullSerializable<SecretAttributes>
{
    [PackedBinaryMember(1)]
    public string Value { get; set; }
    
    public static implicit operator SecretAttributes(string value) => new() { Value = value };
}