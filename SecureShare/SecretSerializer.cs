using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecureShare;

public class SecretSerializer
{
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

    private static class Mapper
    {
        public static Serialized<TAttributes> ToSerialized<TAttributes, TProtected>(
            SealedSecretValue<TAttributes, TProtected> value
        ) => new(value.Id, value.Attributes, BytesToString(value.Protected), value.Version, value.KeyId);

        public static SealedSecretValue<TAttributes, TProtected> FromSerialized<TAttributes, TProtected>(
            Serialized<TAttributes> value
        ) => new(value.Id, value.Attributes, StringToBytes(value.Protected), value.Version, value.KeyId);

        private static string BytesToString(byte[] value) => Convert.ToBase64String(value);
        private static byte[] StringToBytes(string value) => Convert.FromBase64String(value);
    }
}