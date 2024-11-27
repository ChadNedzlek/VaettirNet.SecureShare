using System;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace VaettirNet.SecureShare.Serialization;

public class FullObjectSerializer
{
    private static FullObjectSerializer Instance { get; } = new ();

    public static FullObjectSerializer Create<T>() => Instance;

    public JsonNode Serialize(object value, Type type) => (JsonObject)JsonSerializer.SerializeToNode(value, type)!;
    public object? Deserialize(JsonNode json, Type type) => json.Deserialize(type);
}