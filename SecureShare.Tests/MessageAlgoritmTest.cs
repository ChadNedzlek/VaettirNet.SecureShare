using System.Text;
using FluentAssertions;
using VaettirNet.SecureShare;

namespace SecureShare.Tests;

public class MessageAlgoritmTest
{
    [Test]
    public void EncryptDecrypt()
    {
        MessageEncryptionAlgorithm alg = new();
        
        byte[] private1 = new byte[500];
        byte[] private2 = new byte[500];
        byte[] public1 = new byte[500];
        byte[] public2 = new byte[500];
        
        alg.TryCreate(private1, out int privateLength1, public1, out int publicLength1);
        alg.TryCreate(private2, out int privateLength2, public2, out int publicLength2);

        byte[] encrypted = new byte[500];
        ReadOnlySpan<byte> inputText = "Test String"u8;
        alg.TryEncryptFor(
                inputText,
                private1[..privateLength1],
                public2[..publicLength2],
                encrypted,
                out int encryptedLength)
            .Should()
            .BeTrue();

        byte[] outputText = new byte[500];
        encrypted[..encryptedLength].Should().NotBeEquivalentTo(inputText.ToArray());
        
        alg.TryDecryptFrom(
                encrypted.AsSpan(0, encryptedLength),
                private2[..privateLength2],
                public1[..publicLength1],
                outputText,
                out int outputLength)
            .Should()
            .BeTrue();
        outputText[..outputLength].Should().BeEquivalentTo(inputText.ToArray());
    }
}