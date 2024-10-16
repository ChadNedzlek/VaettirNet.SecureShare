using System.Text;
using FluentAssertions;
using VaettirNet.SecureShare;
using VaettirNet.SecureShare.Vaults;

namespace SecureShare.Tests;

public class MessageAlgoritmTest
{
    [Test]
    public void EncryptDecrypt()
    {
        VaultCryptographyAlgorithm alg = new();
        
        alg.Create(out PrivateClientInfo private1, out PublicClientInfo public1);
        alg.Create(out PrivateClientInfo private2, out PublicClientInfo public2);

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