using System.Text.Json.Nodes;
using FluentAssertions;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Vaults;

namespace SecureShare.Tests;

public class SerializationTests
{
    [Test]
    public void FullJsonSerializableRoundTrip()
    {
        SecretAttributes value = new() { Value = "Test Value" };
        JsonNode jsonNode = SecretAttributes.GetSerializer().Serialize(value);
        jsonNode.ToJsonString().Should().Be("""{"Value":"Test Value"}""");
        SecretAttributes roundTripped = SecretAttributes.GetSerializer().Deserialize(jsonNode);
        roundTripped.Should().BeEquivalentTo(value);
    }

    [Test]
    public void FullBinarySerializableRoundTrip()
    {            
        SecretAttributes value = new() { Value = "Test Value" };
        Span<byte> buffer = stackalloc byte[100];
        SecretAttributes.GetBinarySerializer().TrySerialize(value, buffer, out int cb).Should().BeTrue();
        SecretAttributes roundTripped = SecretAttributes.GetBinarySerializer().Deserialize(buffer[..cb]);
        roundTripped.Should().BeEquivalentTo(value);
    }
    
    [Test]
    public void BinarySerializableRoundTrip()
    {
        SecretProtectedValue value = new() { ProtValue = "Test Value" };
        Span<byte> buffer = stackalloc byte[100];
        SecretProtectedValue.GetBinarySerializer().TrySerialize(value, buffer, out int cb).Should().BeTrue();
        SecretProtectedValue roundTripped = SecretProtectedValue.GetBinarySerializer().Deserialize(buffer[..cb]);
        roundTripped.Should().BeEquivalentTo(value);
    }
    
    [Test]
    public void TooSmallFailsWithFalse()
    {
        SecretProtectedValue value = new() { ProtValue = "Test Value" };
        Span<byte> buffer = stackalloc byte[1];
        SecretProtectedValue.GetBinarySerializer().TrySerialize(value, buffer, out _).Should().BeFalse();
    }

    [Test]
    public void UpdateChangesVersion()
    {
        SecretTransformer transformer = SecretTransformer.CreateRandom();
        OpenVaultReader<SecretAttributes, SecretProtectedValue> store = OpenVaultReader<SecretAttributes, SecretProtectedValue>.FromSnapshot(
            new UntypedVaultSnapshot(VaultIdentifier.Create<SecretAttributes, SecretProtectedValue>(), [], [])
        );
        OpenVaultReader<SecretAttributes, SecretProtectedValue>.Writer writer = store.GetWriter(transformer);
        Guid id = writer.Add(new SecretAttributes{Value = "Attribute Value"}, new SecretProtectedValue{ProtValue = "Protected Value"});
        SealedSecret<SecretAttributes, SecretProtectedValue> sealedSecret = store.Get(id);
        sealedSecret.Version.Should().Be(1);
        sealedSecret.Attributes.Value.Should().Be("Attribute Value");
        writer.Update(id, "Different Value", "Protected Value");
        SealedSecret<SecretAttributes, SecretProtectedValue> modifiedAttr = store.Get(id);
        modifiedAttr.Version.Should().Be(2);
        modifiedAttr.Attributes.Value.Should().Be("Different Value");
        Convert.ToBase64String(modifiedAttr.HashBytes.Span).Should().NotBeEquivalentTo(Convert.ToBase64String(sealedSecret.HashBytes.Span));
        writer.Update(id, "Different Value", "Different Protected Value");
        SealedSecret<SecretAttributes, SecretProtectedValue> modifiedProtectedS = store.Get(id);
        modifiedProtectedS.Version.Should().Be(3);
        modifiedProtectedS.Attributes.Value.Should().Be("Different Value");
        Convert.ToBase64String(modifiedProtectedS.HashBytes.Span).Should().NotBeEquivalentTo(Convert.ToBase64String(sealedSecret.HashBytes.Span));
        Convert.ToBase64String(modifiedProtectedS.HashBytes.Span).Should().NotBeEquivalentTo(Convert.ToBase64String(modifiedAttr.HashBytes.Span));
        writer.Update(id, "Attribute Value", "Protected Value");
        SealedSecret<SecretAttributes, SecretProtectedValue> reset = store.Get(id);
        reset.Version.Should().Be(4);
        Convert.ToBase64String(reset.HashBytes.Span).Should().BeEquivalentTo(Convert.ToBase64String(sealedSecret.HashBytes.Span));
    }
}