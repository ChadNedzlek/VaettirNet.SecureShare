using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Serialization;

namespace SecureShare.Tests;

[PackedBinarySerializable]
public class SecretProtectedValue : BinarySerializable<SecretProtectedValue>
{
    [PackedBinaryMember(1)]
    public string ProtValue { get; set; }

    public static implicit operator SecretProtectedValue(string value) => new() { ProtValue = value };
}