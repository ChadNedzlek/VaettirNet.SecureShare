using System;
using System.Text.Json.Nodes;

namespace VaettirNet.SecureShare.Serialization;

public abstract class FullSerializable<TSelf> : BinarySerializable<TSelf>, IJsonSerializable<TSelf> where TSelf : FullSerializable<TSelf>
{
    static IJsonSerializer<TSelf> IJsonSerializable<TSelf>.GetSerializer() => Serializer.Instance;
    public new static Serializer GetSerializer() => Serializer.Instance;

    public new class Serializer : BinarySerializable<TSelf>.Serializer, IJsonSerializer<TSelf>
    {
        public new static Serializer Instance { get; } = new();
        private static readonly FullObjectSerializer s_objectSerializer = FullObjectSerializer.Create<TSelf>();

        public JsonNode Serialize(TSelf value) => s_objectSerializer.Serialize(value, typeof(TSelf));

        public TSelf Deserialize(JsonNode json) => (TSelf)s_objectSerializer.Deserialize(json, typeof(TSelf))!;
    }
}

public abstract class BinarySerializable<TSelf> : IBinarySerializable<TSelf> where TSelf : BinarySerializable<TSelf>
{
    static IBinarySerializer<TSelf> IBinarySerializable<TSelf>.GetBinarySerializer() => Serializer.Instance;
    public static Serializer GetSerializer() => Serializer.Instance;

    public class Serializer : IBinarySerializer<TSelf>
    {
        public static Serializer Instance { get; } = new();
        private static readonly FullObjectSerializer s_objectSerializer = FullObjectSerializer.Create<TSelf>();

        public bool TrySerialize(TSelf value, Span<byte> destination, out int bytesWritten) => s_objectSerializer.TrySerialize(value, typeof(TSelf), destination, out bytesWritten);

        public TSelf Deserialize(ReadOnlySpan<byte> source) => (TSelf)s_objectSerializer.Deserialize(source, typeof(TSelf));
    }
}