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
        SealedSecretValue<SecretAttributes, SecretProtectedValue> sealedValue = s.Seal(rawValue);
        UnsealedSecretValue<SecretAttributes, SecretProtectedValue> outputValue = s.Unseal(sealedValue);
        outputValue.Should().BeEquivalentTo(rawValue);
    }
}