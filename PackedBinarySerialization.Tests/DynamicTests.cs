using System;
using System.Buffers;
using System.Linq;
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
        WeirdThing input = new WeirdThing { IntField = 0x666, SecondField = 0x444, ArrayProperty = [0x777, 0x888], SecondArrayProperty = [0x111, 0x222] };
        s.Serialize(
            buffer,
            input,
            options
        );
        int tag = s.Deserialize<int>(buffer.WrittenSpan, new PackedBinarySerializationOptions(UsePackedEncoding:true));
        tag.Should().Be(0);

        WeirdThing roundTripped = s.Deserialize<WeirdThing>(buffer.WrittenSpan, options);
        roundTripped.Should().BeEquivalentTo(input, o => o.Excluding(t => t.Ignored));
    }
    
    [TestCase(true)]
    [TestCase(false)]
    public void SerializeNullTag(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        s.Serialize<WeirdThing>(buffer, null, options);
        int tag = s.Deserialize<int>(buffer.WrittenSpan, new PackedBinarySerializationOptions(UsePackedEncoding:true));
        tag.Should().Be(-1);
        WeirdThing roundTripped = s.Deserialize<WeirdThing>(buffer.WrittenSpan, options);
        roundTripped.Should().BeNull();
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
        SubWeirdThing input = new() { IntField = 0x666, SecondField = 0x444, ArrayProperty = [0x777, 0x888], SecondArrayProperty = [0x111, 0x222], SubField = 0x555};
        s.Serialize<WeirdThing>(
            buffer,
            input,
            options
        );
        int tag = s.Deserialize<int>(buffer.WrittenSpan, new PackedBinarySerializationOptions(UsePackedEncoding:true));
        tag.Should().Be(0x333);
        WeirdThing roundTripped = s.Deserialize<WeirdThing>(buffer.WrittenSpan, options);
        roundTripped.Should().BeEquivalentTo(input, o => o.Excluding(t => t.Ignored));
    }
    
    [TestCase(true)]
    [TestCase(false)]
    public void SerializeNoIgnoredMembersMembers(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        WeirdThing input = new() { Ignored = 0x44};
        s.Serialize(
            buffer,
            input,
            options
        );
        buffer.WrittenSpan.ToArray().Should().NotContain(0x44);
        WeirdThing roundTripped = s.Deserialize<WeirdThing>(buffer.WrittenSpan, options);
        roundTripped.Should().BeEquivalentTo(input, o => o.Excluding(t => t.Ignored));
    }
    
    [TestCase(true)]
    [TestCase(false)]
    public void SerializeExplicitMembers(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        ExplicitMembers input = new() { A = 11, B = 22, C = 3, D = 44, E = 5};
        s.Serialize(
            buffer,
            input,
            options
        );
        int bIndex = buffer.WrittenSpan.ToArray().ToList().IndexOf(22);
        int aIndex = buffer.WrittenSpan.ToArray().ToList().IndexOf(11);
        aIndex.Should().BeGreaterThan(bIndex);
        ExplicitMembers roundTripped = s.Deserialize<ExplicitMembers>(buffer.WrittenSpan, options);
        roundTripped.Should().BeEquivalentTo(input, o => o.Excluding(t => t.E));
    }
    
    [TestCase(true)]
    [TestCase(false)]
    public void AddType(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        s.AddType<AbstractTestValue>().AddSubType<DerivedTestValue>(7).WithMemberLayout(PackedBinaryMemberLayout.Sequential);
        DerivedTestValue input = new() { BaseValue = 0x11, DerivedValue = 0x44};
        s.Serialize<AbstractTestValue>(buffer, input, options);
        AbstractTestValue roundTripped = s.Deserialize<AbstractTestValue>(buffer.WrittenSpan, options);
        roundTripped.Should().BeOfType<DerivedTestValue>().And.BeEquivalentTo(input);
    }
    
    [TestCase(true)]
    [TestCase(false)]
    public void SetSurrogate(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        DateTimeOffset value = DateTimeOffset.UtcNow;
        Action serializeDateTimeOffset = () => s.Serialize(buffer, value, options);
        serializeDateTimeOffset.Should().Throw<ArgumentException>();
        buffer.ResetWrittenCount();
        s.SetSurrogate<DateTimeOffset, long>(d => d.UtcTicks, t => new DateTimeOffset(t, TimeSpan.Zero));
        s.Serialize(buffer, value, options);
        DateTimeOffset roundTripped = s.Deserialize<DateTimeOffset>(buffer.WrittenSpan, options);
        roundTripped.Should().Be(value);
    }
    
    [TestCase(true)]
    [TestCase(false)]
    public void GenericTypes(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        var input = new GenericType<string> { Value = 0x55, GenValue = "Pizza" };
        s.Serialize(buffer, input, options);
        var roundTripped = s.Deserialize<GenericType<string>>(buffer.WrittenSpan, options);
        roundTripped.Should().BeEquivalentTo(input);
    }

    [PackedBinarySerializable(MemberLayout = PackedBinaryMemberLayout.Sequential)]
    [PackedBinaryIncludeType(0x333, typeof(SubWeirdThing))]
    private class WeirdThing
    {
        public int IntField;
        public int SecondField;
        public int[] ArrayProperty { get; set; }
        public int[] SecondArrayProperty { get; set; }
        
        [PackedBinaryMemberIgnore]
        public int Ignored { get; set; }
    }
    
    [PackedBinarySerializable(MemberLayout = PackedBinaryMemberLayout.Sequential)]
    private class SubWeirdThing : WeirdThing
    {
        public int SubField;
    }

    [PackedBinarySerializable(MemberLayout = PackedBinaryMemberLayout.Sequential)]
    private class ObjHolder
    {
        [PackedBinaryIncludeType(0x999, typeof(WeirdThing))]
        public object Obj { get; set; }
    }

    [PackedBinarySerializable(MemberLayout = PackedBinaryMemberLayout.Explicit)]
    private class ExplicitMembers
    {
        [PackedBinaryMember(2)]
        public required int A;
        [PackedBinaryMember(1)]
        public required int B;
        [PackedBinaryMember(3)]
        public required int C;
        [PackedBinaryMember(2)]
        public required int D;
        
        public required int E;
    }

    public abstract class AbstractTestValue
    {
        public int BaseValue { get; set; }
    }

    public class DerivedTestValue : AbstractTestValue
    {
        public int DerivedValue { get; set; }
    }

    [PackedBinarySerializable(MemberLayout = PackedBinaryMemberLayout.Sequential)]
    public class GenericType<T>
    {
        public int Value { get; set; }
        public T GenValue { get; set; }
    }
}