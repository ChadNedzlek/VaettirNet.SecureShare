using FluentAssertions;
using VaettirNet.SecureShare.Secrets;

namespace SecureShare.Tests;

public class TransformerTests
{
    [Test]
    public void SealUnseal()
    {
        SecretTransformer s = SecretTransformer.CreateRandom();
        UnsealedSecretValue<SecretAttributes, SecretProtectedValue> rawValue = new(Guid.NewGuid(),
            new() { Value = "attribute value" },
            new() { ProtValue = "Secret Cheese" }
        );
        SealedSecretSecret<SecretAttributes, SecretProtectedValue> sealedSecret = s.Seal(rawValue);
        UnsealedSecretValue<SecretAttributes, SecretProtectedValue> outputValue = s.Unseal(sealedSecret);
        outputValue.Should().BeEquivalentTo(rawValue);
    }
}