using FluentAssertions;

namespace SecureShare.Tests;

public class TransformerTests
{
    [Test]
    public void SealUnseal()
    {
        SecretTransformer s = SecretTransformer.CreateRandom();
        Pizza rawValue = new(Guid.NewGuid(),
            new PizzaName("First Pizza"),
            new PizzaToppings { Pepperoni = true, CheeseType = "Secret Cheese" });
        SealedSecretValue<PizzaName, PizzaToppings> sealedValue = s.Seal(rawValue);
        UnsealedSecretValue<PizzaName, PizzaToppings> outputValue = s.Unseal(sealedValue);
        outputValue.Should().BeEquivalentTo(rawValue);
    }
}