using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Tests;

[PackedBinarySerializable]
public class SecretProtectedValue : BinarySerializable<SecretProtectedValue>
{
    [PackedBinaryMember(1)]
    public string ProtValue { get; set; }

    public static implicit operator SecretProtectedValue(string value)
    {
        return new SecretProtectedValue { ProtValue = value };
    }
}