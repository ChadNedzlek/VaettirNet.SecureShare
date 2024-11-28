using System;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.SecureShare.Tests;

public class TestValue
{
    [PackedBinaryMember(1)]
    public Guid Id { get; private set; }
}