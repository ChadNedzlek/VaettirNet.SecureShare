using System;
using System.Collections.Immutable;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Secrets;

public class SecretSerializer
{
    public SealedSecretValue<TAttributes, TProtected> Deserialize<TAttributes, TProtected>(string data) where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes> where TProtected : IBinarySerializable<TProtected>
    {
        var serialized = JsonSerializer.Deserialize<Serialized<TAttributes>>(data)!;
        return Mapper.FromSerialized<TAttributes, TProtected>(serialized);
    }

    public string Serialize<TAttributes, TProtected>(SealedSecretValue<TAttributes, TProtected> secret) where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes> where TProtected : IBinarySerializable<TProtected>
    {
        Serialized<TAttributes> serialized = Mapper.ToSerialized(secret);
        return JsonSerializer.Serialize(serialized);
    }

    private class Serialized<TAttributes>
    {
        public Serialized(Guid id, TAttributes attributes, ReadOnlyMemory<byte> @protected, int version, int keyId, ReadOnlyMemory<byte> hashBytes)
        {
            Id = id;
            Version = version;
            KeyId = keyId;
            Attributes = attributes;
            Protected = @protected;
            HashBytes = hashBytes;
        }

        public Guid Id { get; }

        [JsonPropertyName("v")]
        public int Version { get; }

        [JsonPropertyName("k")]
        public int KeyId { get; }

        [JsonPropertyName("a")]
        public TAttributes Attributes { get; }

        [JsonPropertyName("p")]
        public ReadOnlyMemory<byte> Protected { get; }

        [JsonPropertyName("h")]
        public ReadOnlyMemory<byte> HashBytes { get; }
    }

    private static class Mapper
    {
        public static Serialized<TAttributes> ToSerialized<TAttributes, TProtected>(SealedSecretValue<TAttributes, TProtected> value)
            where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
            where TProtected : IBinarySerializable<TProtected>
        {
            return new Serialized<TAttributes>(value.Id, value.Attributes, value.Protected, value.Version, value.KeyId, value.HashBytes);
        }

        public static SealedSecretValue<TAttributes, TProtected> FromSerialized<TAttributes, TProtected>(Serialized<TAttributes> value)
            where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
            where TProtected : IBinarySerializable<TProtected>
        {
            return new SealedSecretValue<TAttributes, TProtected>(
                value.Id,
                value.Attributes,
                value.Protected,
                value.Version,
                value.KeyId,
                value.HashBytes
            );
        }
    }
}