using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using FluentAssertions;
using NUnit.Framework;
using VaettirNet.SecureShare.Common;

namespace VaettirNet.PackedBinarySerialization.Tests;

public class CollectionTests
{
    [TestCase(true, true)]
    [TestCase(false, true)]
    [TestCase(true, false)]
    [TestCase(false, false)]
    public void ArrayRoundTrip(bool packed, bool implicitRepeat)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed, ImplicitRepeat: implicitRepeat);
        buffer.ResetWrittenCount();
        int[] expected = new []{1,2,3,4,5, -1, -200, 1_000_000};
        s.Serialize(buffer, expected, options);
        int[] roundTrippedValue = s.Deserialize<int[]>(buffer.WrittenSpan, options);
        roundTrippedValue.Should().BeEquivalentTo(expected);
    }
    
    [TestCase(true)]
    [TestCase(false)]
    public void NullArrayRoundTrip(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        buffer.ResetWrittenCount();
        s.Serialize<int[]>(buffer, null, options);
        int[] roundTrippedValue = s.Deserialize<int[]>(buffer.WrittenSpan, options);
        roundTrippedValue.Should().BeNull();
    }
    
    [TestCase(true)]
    [TestCase(false)]
    public void EmptyArrayRoundTrip(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        buffer.ResetWrittenCount();
        s.Serialize<int[]>(buffer, [], options);
        int[] roundTrippedValue = s.Deserialize<int[]>(buffer.WrittenSpan, options);
        roundTrippedValue.Should().BeEmpty();
    }
    
    [TestCase(true)]
    [TestCase(false)]
    public static void MemoryRoundTrip(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        buffer.ResetWrittenCount();
        ReadOnlyMemory<int> expected = new []{1,2,3,4,5, -1, -200, 1_000_000};
        s.Serialize(buffer, expected, options);
        var roundTrippedValue = s.Deserialize<ReadOnlyMemory<int>>(buffer.WrittenSpan, options);
        roundTrippedValue.Should().BeEquivalentTo(expected, o => o.Using(new MemoryComparer<int>()));
    }

    [TestCase(true, true)]
    [TestCase(false, true)]
    [TestCase(true, false)]
    [TestCase(false, false)]
    public void Lists(bool packed, bool implicitRepeat)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed, ImplicitRepeat: implicitRepeat);
        buffer.ResetWrittenCount();
        List<int> expected = [1,2,3,4,5, -1, -200, 1_000_000];
        s.Serialize(buffer, expected, options);
        var roundTrippedValue = s.Deserialize<List<int>>(buffer.WrittenSpan, options);
        roundTrippedValue.Should().BeEquivalentTo(expected, o => o.Using(new MemoryComparer<int>()));
    }
    
    [TestCase(true, true)]
    [TestCase(false, true)]
    [TestCase(true, false)]
    [TestCase(false, false)]
    public void IEnumerable(bool packed, bool implicitRepeat)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed, ImplicitRepeat: implicitRepeat);
        buffer.ResetWrittenCount();
        IEnumerable<int> expected = [1,2,3,4,5, -1, -200, 1_000_000];
        s.Serialize(buffer, expected, options);
        var roundTrippedValue = s.Deserialize<IEnumerable<int>>(buffer.WrittenSpan, options);
        roundTrippedValue.Should().BeEquivalentTo(expected, o => o.Using(new MemoryComparer<int>()));
    }
    
    [TestCase(true, true)]
    [TestCase(false, true)]
    [TestCase(true, false)]
    [TestCase(false, false)]
    public void IReadOnlyList(bool packed, bool implicitRepeat)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed, ImplicitRepeat: implicitRepeat);
        buffer.ResetWrittenCount();
        IReadOnlyList<int> expected = [1,2,3,4,5, -1, -200, 1_000_000];
        s.Serialize(buffer, expected, options);
        var roundTrippedValue = s.Deserialize<IReadOnlyList<int>>(buffer.WrittenSpan, options);
        roundTrippedValue.Should().BeEquivalentTo(expected, o => o.Using(new MemoryComparer<int>()));
    }

    [TestCase(true, true)]
    [TestCase(false, true)]
    [TestCase(true, false)]
    [TestCase(false, false)]
    public void ImmutableLists(bool packed, bool implicitRepeat)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed, ImplicitRepeat: implicitRepeat);
        buffer.ResetWrittenCount();
        ImmutableList<int> expected = [1,2,3,4,5, -1, -200, 1_000_000];
        s.Serialize(buffer, expected, options);
        var roundTrippedValue = s.Deserialize<ImmutableList<int>>(buffer.WrittenSpan, options);
        roundTrippedValue.Should().BeEquivalentTo(expected, o => o.Using(new MemoryComparer<int>()));
    }

    [TestCase(true, true)]
    [TestCase(false, true)]
    [TestCase(true, false)]
    [TestCase(false, false)]
    public void ImmutableSortedSet(bool packed, bool implicitRepeat)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed, ImplicitRepeat: implicitRepeat);
        buffer.ResetWrittenCount();
        ImmutableSortedSet<int> expected = [1,2,3,4,5, -1, -200, 1_000_000];
        s.Serialize(buffer, expected, options);
        var roundTrippedValue = s.Deserialize<ImmutableSortedSet<int>>(buffer.WrittenSpan, options);
        roundTrippedValue.Should().BeEquivalentTo(expected, o => o.Using(new MemoryComparer<int>()));
    }
}