using System;
using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecureShare;

public class SecretSerializer
{
    public SealedSecretValue<TAttributes, TProtected> Deserialize<TAttributes, TProtected>(string data)
    {
        var serialized = JsonSerializer.Deserialize<Serialized<TAttributes>>(data)!;
        return Mapper.FromSerialized<TAttributes, TProtected>(serialized);
    }

    public string Serialize<TAttributes, TProtected>(SealedSecretValue<TAttributes, TProtected> secret)
    {
        Serialized<TAttributes> serialized = Mapper.ToSerialized(secret);
        return JsonSerializer.Serialize(serialized);
    }

    private class Serialized<TAttributes>
    {
        public Serialized(Guid id, TAttributes attributes, string @protected, int version, int keyId)
        {
            Id = id;
            Version = version;
            KeyId = keyId;
            Attributes = attributes;
            Protected = @protected;
        }

        public Guid Id { get; }

        [JsonPropertyName("v")]
        public int Version { get; }

        [JsonPropertyName("k")]
        public int KeyId { get; }

        [JsonPropertyName("a")]
        public TAttributes Attributes { get; }

        [JsonPropertyName("p")]
        public string Protected { get; }
    }

    private static class Mapper
    {
        public static Serialized<TAttributes> ToSerialized<TAttributes, TProtected>(
            SealedSecretValue<TAttributes, TProtected> value
        )
        {
            return new Serialized<TAttributes>(value.Id, value.Attributes, BytesToString(value.Protected), value.Version, value.KeyId);
        }

        public static SealedSecretValue<TAttributes, TProtected> FromSerialized<TAttributes, TProtected>(
            Serialized<TAttributes> value
        )
        {
            return new SealedSecretValue<TAttributes, TProtected>(value.Id,
                value.Attributes,
                StringToBytes(value.Protected),
                value.Version,
                value.KeyId);
        }

        private static string BytesToString(ImmutableArray<byte> value)
        {
            return Convert.ToBase64String(value.AsSpan());
        }

        private static ImmutableArray<byte> StringToBytes(string value)
        {
            return Convert.FromBase64String(value).ToImmutableArray();
        }
    }
}