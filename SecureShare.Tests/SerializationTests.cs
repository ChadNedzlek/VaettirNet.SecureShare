using System.Text.Json.Nodes;
using FluentAssertions;
using ProtoBuf;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Serialization;

namespace SecureShare.Tests;

public class SerializationTests
{
    [Test]
    public void FullJsonSerializableRoundTripe()
    {
        SecretAttributes value = new() { Value = "Test Value" };
        JsonNode jsonNode = SecretAttributes.GetSerializer().Serialize(value);
        jsonNode.ToJsonString().Should().Be("""{"Value":"Test Value"}""");
        var roundTripped = SecretAttributes.GetSerializer().Deserialize(jsonNode);
        roundTripped.Should().BeEquivalentTo(value);
    }
    [Test]
    
    public void FullBinarySerializableRoundTripe()
    {
        SecretAttributes value = new() { Value = "Test Value" };
        Span<byte> buffer = stackalloc byte[100];
        SecretAttributes.GetSerializer().TrySerialize(value, buffer, out int cb).Should().BeTrue();
        SecretAttributes roundTripped = SecretAttributes.GetSerializer().Deserialize(buffer[..cb]);
        roundTripped.Should().BeEquivalentTo(value);
    }
    
    [Test]
    public void BinarySerializableRoundTripe()
    {
        SecretProtectedValue value = new() { ProtValue = "Test Value" };
        Span<byte> buffer = stackalloc byte[100];
        SecretProtectedValue.GetSerializer().TrySerialize(value, buffer, out int cb).Should().BeTrue();
        SecretProtectedValue roundTripped = SecretProtectedValue.GetSerializer().Deserialize(buffer[..cb]);
        roundTripped.Should().BeEquivalentTo(value);
    }

    [Test]
    public void UpdateChangesVersion()
    {
        SecretStore<SecretAttributes, SecretProtectedValue> store = new(SecretTransformer.CreateRandom());
        Guid id = store.Add("Attribute Value", "Protected Value");
        var sealedValue = store.Get(id);
        sealedValue.Version.Should().Be(1);
        sealedValue.Attributes.Value.Should().Be("Attribute Value");
        store.Set(new UnsealedSecretValue<SecretAttributes, SecretProtectedValue>(id, "Different Value", "Protected Value"));
        var modifiedAttr = store.Get(id);
        modifiedAttr.Version.Should().Be(2);
        modifiedAttr.Attributes.Value.Should().Be("Different Value");
        Convert.ToBase64String(modifiedAttr.HashBytes.Span).Should().NotBeEquivalentTo(Convert.ToBase64String(sealedValue.HashBytes.Span));
        store.Set(new UnsealedSecretValue<SecretAttributes, SecretProtectedValue>(id, "Different Value", "Different Protected Value"));
        var modifiedProtectedS = store.Get(id);
        modifiedProtectedS.Version.Should().Be(3);
        modifiedProtectedS.Attributes.Value.Should().Be("Different Value");
        Convert.ToBase64String(modifiedProtectedS.HashBytes.Span).Should().NotBeEquivalentTo(Convert.ToBase64String(sealedValue.HashBytes.Span));
        Convert.ToBase64String(modifiedProtectedS.HashBytes.Span).Should().NotBeEquivalentTo(Convert.ToBase64String(modifiedAttr.HashBytes.Span));
        store.Set(new UnsealedSecretValue<SecretAttributes, SecretProtectedValue>(id, "Attribute Value", "Protected Value"));
        var reset = store.Get(id);
        reset.Version.Should().Be(4);
        Convert.ToBase64String(reset.HashBytes.Span).Should().BeEquivalentTo(Convert.ToBase64String(sealedValue.HashBytes.Span));
    }
}

[ProtoContract]
public class SecretProtectedValue : BinarySerializable<SecretProtectedValue>
{
    [ProtoMember(1)]
    public string ProtValue { get; set; }

    public static implicit operator SecretProtectedValue(string value) => new() { ProtValue = value };
}

[ProtoContract]
public class SecretAttributes : FullSerializable<SecretAttributes>
{
    [ProtoMember(1)]
    public string Value { get; set; }
    
    public static implicit operator SecretAttributes(string value) => new() { Value = value };
}