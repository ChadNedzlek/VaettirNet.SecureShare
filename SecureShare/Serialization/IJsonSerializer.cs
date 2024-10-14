using System.Text.Json.Nodes;

namespace VaettirNet.SecureShare.Serialization;

public interface IJsonSerializer<T> where T : IJsonSerializable<T>
{
    JsonNode Serialize(T value);
    T Deserialize(JsonNode json);
}