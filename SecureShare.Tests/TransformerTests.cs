using System;
using FluentAssertions;
using NUnit.Framework;
using VaettirNet.SecureShare.Secrets;

namespace VaettirNet.SecureShare.Tests;

public class TransformerTests
{
    [Test]
    public void SealUnseal()
    {
        SecretTransformer s = SecretTransformer.CreateRandom();
        UnsealedSecret<SecretAttributes, SecretProtectedValue> rawValue = new(Guid.NewGuid(),
            new() { Value = "attribute value" },
            new() { ProtValue = "Secret Cheese" }
        );
        SealedSecret<SecretAttributes, SecretProtectedValue> sealedSecret = s.Seal(rawValue);
        UnsealedSecret<SecretAttributes, SecretProtectedValue> outputValue = s.Unseal(sealedSecret);
        outputValue.Should().BeEquivalentTo(rawValue);
    }
}