using System.Buffers;
using System.Runtime.InteropServices;
using NUnit.Framework;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.PackedBinarySerialization.Tests;

public class DynamicTests
{
    [TestCase(true)]
    [TestCase(false)]
    public void SerializeDynamic(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        s.Serialize(buffer, new WeirdThing{IntField = 0x666, SecondField = 0x444, ArrayProperty = [0x777, 0x888], SecondArrayProperty = [0x111, 0x222]});
    }

    [PackedBinarySerializable(SequentialMembers = true)]
    [StructLayout(LayoutKind.Sequential)]
    private class WeirdThing
    {
        public int IntField;
        public int SecondField;
        public int[] ArrayProperty { get; set; }
        public int[] SecondArrayProperty { get; set; }
    }
}