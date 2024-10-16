using System;
using System.Text.Json.Nodes;

namespace VaettirNet.SecureShare.Serialization;

public abstract class FullSerializable<TSelf> : BinarySerializable<TSelf>, IJsonSerializable<TSelf> where TSelf : FullSerializable<TSelf>
{
    public static IJsonSerializer<TSelf> GetSerializer() => Serializer.Instance;

    public new class Serializer : IJsonSerializer<TSelf>
    {
        public new static Serializer Instance { get; } = new();
        private static readonly FullObjectSerializer s_objectSerializer = FullObjectSerializer.Create<TSelf>();

        public JsonNode Serialize(TSelf value) => s_objectSerializer.Serialize(value, typeof(TSelf));

        public TSelf Deserialize(JsonNode json) => (TSelf)s_objectSerializer.Deserialize(json, typeof(TSelf))!;
    }
}

public abstract class BinarySerializable<TSelf> : IBinarySerializable<TSelf> where TSelf : BinarySerializable<TSelf>
{
    public static IBinarySerializer<TSelf> GetBinarySerializer() => ProtobufObjectSerializer.Create<TSelf>();
}