using System.Text.Json.Nodes;

namespace VaettirNet.SecureShare.Serialization;

public abstract class FullSerializable<TSelf> : BinarySerializable<TSelf>, IJsonSerializable<TSelf> where TSelf : FullSerializable<TSelf>
{
    public static IJsonSerializer<TSelf> GetSerializer() => Serializer.Instance;

    public class Serializer : IJsonSerializer<TSelf>
    {
        public static Serializer Instance { get; } = new();
        private static readonly FullObjectSerializer s_objectSerializer = FullObjectSerializer.Create<TSelf>();

        public JsonNode Serialize(TSelf value) => s_objectSerializer.Serialize(value, typeof(TSelf));

        public TSelf Deserialize(JsonNode json) => (TSelf)s_objectSerializer.Deserialize(json, typeof(TSelf))!;
    }
}