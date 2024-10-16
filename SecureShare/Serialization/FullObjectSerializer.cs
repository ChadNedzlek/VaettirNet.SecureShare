using System;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace VaettirNet.SecureShare.Serialization;

public class FullObjectSerializer : ProtobufObjectSerializer
{
    private static FullObjectSerializer Instance { get; } = new ();

    public new static FullObjectSerializer Create<T>()
    {
        ValidateType(typeof(T));
        return Instance;
    }
    
    protected new static void ValidateType(Type type) {
        ProtobufObjectSerializer.ValidateType(type);
    }

    public JsonNode Serialize(object value, Type type) => (JsonObject)JsonSerializer.SerializeToNode(value, type)!;
    public object? Deserialize(JsonNode json, Type type) => json.Deserialize(type);
}