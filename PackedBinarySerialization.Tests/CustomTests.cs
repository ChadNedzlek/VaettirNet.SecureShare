using System.Buffers;
using FluentAssertions;
using NUnit.Framework;

namespace VaettirNet.PackedBinarySerialization.Tests;

public class CustomTests
{
    [TestCase(true)]
    [TestCase(false)]
    public void RefType(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        RefTypeObject expected = new(500, "A string");
        s.Serialize(buffer, expected, options);
        var read = s.Deserialize<RefTypeObject>(buffer.WrittenSpan, options);
        read.Should().BeEquivalentTo(expected);
    }

    public class RefTypeObject : IPackedBinarySerializable<RefTypeObject>
    {
        public int Value { get; }
        public string Str { get; }

        public RefTypeObject(int value, string str)
        {
            Value = value;
            Str = str;
        }

        public static RefTypeObject Read<TReader>(ref PackedBinaryReader<TReader> reader, PackedBinarySerializationContext ctx)
            where TReader : IBufferReader<byte>, allows ref struct
        {
            return new RefTypeObject(reader.ReadInt32(ctx), reader.ReadString(ctx));
        }

        public int Write<TWriter>(ref PackedBinaryWriter<TWriter> writer, PackedBinarySerializationContext ctx)
            where TWriter : IBufferWriter<byte>, allows ref struct
        {
            int written = writer.WriteInt32(Value, ctx);
            written += writer.WriteString(Str, ctx);
            return written;
        }
    }
}