using System.Buffers;

namespace VaettirNet.PackedBinarySerialization;

public interface IPackedBinarySerializable<out T> : IPackedBinarySerializable
{
    static abstract T Read<TReader>(ref PackedBinaryReader<TReader> reader, PackedBinarySerializationContext ctx)
        where TReader : IBufferReader<byte>, allows ref struct;
}

public interface IPackedBinarySerializable
{
    int Write<TWriter>(ref PackedBinaryWriter<TWriter> writer, PackedBinarySerializationContext ctx)
        where TWriter : IBufferWriter<byte>, allows ref struct;
}