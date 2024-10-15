using System.Text;
using FluentAssertions;
using VaettirNet.SecureShare;

namespace SecureShare.Tests;

public class MessageAlgoritmTest
{
    [Test]
    public void EncryptDecrypt()
    {
        VaultCryptographyAlgorithm alg = new();
        
        alg.Create(out var private1, out var public1);
        alg.Create(out var private2, out var public2);

        byte[] encrypted = new byte[500];
        ReadOnlySpan<byte> inputText = "Test String"u8;
        alg.TryEncryptFor(
                inputText,
                private1.EncryptionKey.Span,
                public2.EncryptionKey.Span,
                encrypted,
                out int encryptedLength)
            .Should()
            .BeTrue();

        byte[] outputText = new byte[500];
        encrypted[..encryptedLength].Should().NotBeEquivalentTo(inputText.ToArray());
        
        alg.TryDecryptFrom(
                encrypted.AsSpan(0, encryptedLength),
                private2.EncryptionKey.Span,
                public1.EncryptionKey.Span,
                outputText,
                out int outputLength)
            .Should()
            .BeTrue();
        outputText[..outputLength].Should().BeEquivalentTo(inputText.ToArray());
    }
}