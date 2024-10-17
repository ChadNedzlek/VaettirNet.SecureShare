using System.Text.Json.Nodes;
using FluentAssertions;
using ProtoBuf;
using ProtoBuf.Meta;
using VaettirNet.SecureShare.Secrets;

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
        SecretStore<SecretAttributes, SecretProtectedValue> store = new(SecretTransformer.CreateRandom());
        Guid id = store.Add("Attribute Value", "Protected Value");
        SealedSecretValue<SecretAttributes, SecretProtectedValue> sealedValue = store.Get(id);
        sealedValue.Version.Should().Be(1);
        sealedValue.Attributes.Value.Should().Be("Attribute Value");
        store.Set(new UnsealedSecretValue<SecretAttributes, SecretProtectedValue>(id, "Different Value", "Protected Value"));
        SealedSecretValue<SecretAttributes, SecretProtectedValue> modifiedAttr = store.Get(id);
        modifiedAttr.Version.Should().Be(2);
        modifiedAttr.Attributes.Value.Should().Be("Different Value");
        Convert.ToBase64String(modifiedAttr.HashBytes.Span).Should().NotBeEquivalentTo(Convert.ToBase64String(sealedValue.HashBytes.Span));
        store.Set(new UnsealedSecretValue<SecretAttributes, SecretProtectedValue>(id, "Different Value", "Different Protected Value"));
        SealedSecretValue<SecretAttributes, SecretProtectedValue> modifiedProtectedS = store.Get(id);
        modifiedProtectedS.Version.Should().Be(3);
        modifiedProtectedS.Attributes.Value.Should().Be("Different Value");
        Convert.ToBase64String(modifiedProtectedS.HashBytes.Span).Should().NotBeEquivalentTo(Convert.ToBase64String(sealedValue.HashBytes.Span));
        Convert.ToBase64String(modifiedProtectedS.HashBytes.Span).Should().NotBeEquivalentTo(Convert.ToBase64String(modifiedAttr.HashBytes.Span));
        store.Set(new UnsealedSecretValue<SecretAttributes, SecretProtectedValue>(id, "Attribute Value", "Protected Value"));
        SealedSecretValue<SecretAttributes, SecretProtectedValue> reset = store.Get(id);
        reset.Version.Should().Be(4);
        Convert.ToBase64String(reset.HashBytes.Span).Should().BeEquivalentTo(Convert.ToBase64String(sealedValue.HashBytes.Span));
    }

    [Test]
    public void Thing()
    {
        RuntimeTypeModel model = RuntimeTypeModel.Create();
        model.Add<Container>();
        model.Add<TestValue>()
            .AddSubType(1, typeof(SubValue<int>));
        var t = model.Compile();
    }
}

public class Container
{
    [ProtoMember(1)]
    public TestValue Value { get; private set; }
}

public class TestValue
{
    [ProtoMember(1)]
    public Guid Id { get; private set; }
}

public class SubValue<T> : TestValue
{
    public SubValue(T value)
    {
        Value = value;
    }

    [ProtoMember(2)]
    public T Value { get; private set; }
}