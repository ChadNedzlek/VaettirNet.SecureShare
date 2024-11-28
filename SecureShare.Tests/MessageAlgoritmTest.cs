using System;
using FluentAssertions;
using NUnit.Framework;
using VaettirNet.SecureShare.Crypto;

namespace VaettirNet.SecureShare.Tests;

public class MessageAlgoritmTest
{
    [Test]
    public void EncryptDecrypt()
    {
        VaultCryptographyAlgorithm alg = new();
        
        alg.CreateKeys(Guid.NewGuid(), out PrivateKeyInfo private1, out PublicKeyInfo public1);
        alg.CreateKeys(Guid.NewGuid(), out PrivateKeyInfo private2, out PublicKeyInfo public2);

        byte[] encrypted = new byte[500];
        ReadOnlySpan<byte> inputText = "Test String"u8;
        alg.TryEncryptFor(
                inputText,
                private1,
                public2,
                encrypted,
                out int encryptedLength)
            .Should()
            .BeTrue();

        byte[] outputText = new byte[500];
        encrypted[..encryptedLength].Should().NotBeEquivalentTo(inputText.ToArray());
        
        alg.TryDecryptFrom(
                encrypted.AsSpan(0, encryptedLength),
                private2,
                public1,
                outputText,
                out int outputLength)
            .Should()
            .BeTrue();
        outputText[..outputLength].Should().BeEquivalentTo(inputText.ToArray());
    }
}