using System.Text;

namespace VaettirNet.PackedBinarySerialization;

public record class PackedBinarySerializationOptions(Encoding? Encoding = null, bool UsePackedEncoding = false, bool ImplicitRepeat = false);