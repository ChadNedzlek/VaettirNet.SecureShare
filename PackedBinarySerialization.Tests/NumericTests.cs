using System;
using System.Buffers;
using FluentAssertions;
using NUnit.Framework;

namespace VaettirNet.PackedBinarySerialization.Tests;

public class NumericTests
{
    [TestCase(0, false)]
    [TestCase(0, true)]
    [TestCase(1, false)]
    [TestCase(1, true)]
    [TestCase(-1, false)]
    [TestCase(-1, true)]
    [TestCase(5, false)]
    [TestCase(5, true)]
    [TestCase(-5, false)]
    [TestCase(-5, true)]
    [TestCase(127, false)]
    [TestCase(127, true)]
    [TestCase(-64, false)]
    [TestCase(-64, true)]
    [TestCase(0xFFF, false)]
    [TestCase(0xFFF, true)]
    [TestCase(-200, false)]
    [TestCase(-200, true)]
    [TestCase(10_000, false)]
    [TestCase(10_000, true)]
    [TestCase(-10_000, false)]
    [TestCase(-10_000, true)]
    [TestCase(10_000_000, false)]
    [TestCase(10_000_000, true)]
    [TestCase(-10_000_000, false)]
    [TestCase(-10_000_000, true)]
    public void NumberRoundTrip(int i, bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        s.Serialize(buffer, i, options);
        int roundTrippedValue = s.Deserialize<int>(buffer.WrittenSpan, options);
        roundTrippedValue.Should().Be(i);
    }
    
    [TestCase(true)]
    [TestCase(false)]
    public void RandomRoundTrip(bool packed)
    {
        PackedBinarySerializer s = new();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1000);
        PackedBinarySerializationOptions options = new(UsePackedEncoding: packed);
        for (int i = 0; i < 1_000_000; i++)
        {
            buffer.ResetWrittenCount();
            long target = Random.Shared.NextInt64();
            s.Serialize(buffer, target, options);
            long roundTrippedValue = s.Deserialize<long>(buffer.WrittenSpan, options);
            roundTrippedValue.Should().Be(target);
        }
    }
}