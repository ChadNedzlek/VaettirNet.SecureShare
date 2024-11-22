using System.Buffers;
using System.Runtime.InteropServices;
using FluentAssertions;
using NUnit.Framework;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.PackedBinarySerialization.Tests;

public class DynamicTests
{
    [TestCase(true)]
    [TestCase(false)]
    public void SerializeDynamicUsesZeroTag(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        s.Serialize(
            buffer,
            new WeirdThing { IntField = 0x666, SecondField = 0x444, ArrayProperty = [0x777, 0x888], SecondArrayProperty = [0x111, 0x222] },
            options
        );
        var tag = s.Deserialize<int>(buffer.WrittenSpan, new PackedBinarySerializationOptions(UsePackedEncoding:true));
        tag.Should().Be(0);
    }
    
    [TestCase(true)]
    [TestCase(false)]
    public void SerializeNullTag(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        s.Serialize<WeirdThing>(buffer, null, options);
        var tag = s.Deserialize<int>(buffer.WrittenSpan, new PackedBinarySerializationOptions(UsePackedEncoding:true));
        tag.Should().Be(-1);
    }
    
    [TestCase(true)]
    [TestCase(false)]
    public void SerializeMemberWithTypeInclude(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        s.Serialize(buffer, new ObjHolder{Obj = new WeirdThing{IntField = 0x555}}, options);
    }
    
    [TestCase(true)]
    [TestCase(false)]
    public void SerializeSubTypeDynamicUsesTag(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        s.Serialize<WeirdThing>(
            buffer,
            new SubWeirdThing { IntField = 0x666, SecondField = 0x444, ArrayProperty = [0x777, 0x888], SecondArrayProperty = [0x111, 0x222], SubField = 0x555},
            options
        );
        var tag = s.Deserialize<int>(buffer.WrittenSpan, new PackedBinarySerializationOptions(UsePackedEncoding:true));
        tag.Should().Be(0x333);
    }

    [PackedBinarySerializable(SequentialMembers = true)]
    [PackedBinaryIncludeType(0x333, typeof(SubWeirdThing))]
    private class WeirdThing
    {
        public int IntField;
        public int SecondField;
        public int[] ArrayProperty { get; set; }
        public int[] SecondArrayProperty { get; set; }
    }
    
    [PackedBinarySerializable(SequentialMembers = true)]
    private class SubWeirdThing : WeirdThing
    {
        public int SubField;
    }

    [PackedBinarySerializable(SequentialMembers = true)]
    private class ObjHolder
    {
        [PackedBinaryIncludeType(0x999, typeof(WeirdThing))]
        public object Obj { get; set; }
    }
}