using System.Text;

namespace VaettirNet.PackedBinarySerialization;

public readonly record struct PackedBinarySerializationContext(Encoding? Encoding, long? MaxValue, bool ImplicitSize, bool UsePackedIntegers)
{
    public PackedBinarySerializationContext Descend() => this with { MaxValue = null, ImplicitSize = false };
}