using FluentAssertions;
using VaettirNet.SecureShare.Secrets;

namespace SecureShare.Tests;

public class TransformerTests
{
    [Test]
    public void SealUnseal()
    {
        SecretTransformer s = SecretTransformer.CreateRandom();
        UnsealedSecretValue<string, string> rawValue = new(Guid.NewGuid(),
            "First Pizza",
            "Secret Cheese");
        SealedSecretValue<string, string> sealedValue = s.Seal(rawValue);
        UnsealedSecretValue<string, string> outputValue = s.Unseal(sealedValue);
        outputValue.Should().BeEquivalentTo(rawValue);
    }
}