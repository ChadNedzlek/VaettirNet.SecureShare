using System;
using System.Buffers;
using System.Collections.Generic;
using FluentAssertions;
using NUnit.Framework;

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
        var roundTrippedValue = s.Deserialize<int[]>(buffer.WrittenSpan, options);
        roundTrippedValue.Should().BeEquivalentTo(expected);
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

    private class MemoryComparer<T> : IEqualityComparer<ReadOnlyMemory<T>>
    {
        private readonly IEqualityComparer<T> _itemComparer;

        public MemoryComparer() : this(EqualityComparer<T>.Default)
        {
        }

        public MemoryComparer(IEqualityComparer<T> itemComparer)
        {
            _itemComparer = itemComparer;
        }

        public bool Equals(ReadOnlyMemory<T> x, ReadOnlyMemory<T> y)
        {
            if (x.Length != y.Length)
            {
                return false;
            }

            ReadOnlySpan<T> a = x.Span, b = y.Span;

            for (int i = 0; i < x.Length; i++)
            {
                if (!_itemComparer.Equals(a[i], b[i]))
                {
                    return false;
                }
            }

            return true;
        }

        public int GetHashCode(ReadOnlyMemory<T> obj)
        {
            HashCode h = new();
            foreach(T i in obj.Span){
                h.Add(_itemComparer.GetHashCode(i));
            }
            return h.ToHashCode();
        }
    }
}