using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryReader<TReader>
{
    public bool TryReadFromMetadata<T>(PackedBinarySerializationContext ctx, [MaybeNullWhen(false)] out T value)
    {
        if (typeof(T).GetCustomAttribute<PackedBinarySerializableAttribute>() is { } attr)
        {
            value = ReadFromMetadataCore<T>(ctx, attr);
            return true;
        }

        value = default;
        return false;
    }

    public T ReadFromMetadata<T>(PackedBinarySerializationContext ctx) =>
        ReadFromMetadataCore<T>(ctx, typeof(T).GetCustomAttribute<PackedBinarySerializableAttribute>()!);



    private T ReadFromMetadataCore<T>(PackedBinarySerializationContext ctx, PackedBinarySerializableAttribute attr)
    {
        throw null;
    }
}