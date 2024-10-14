namespace VaettirNet.SecureShare.Serialization;

public interface IJsonSerializable<TSelf> where TSelf : IJsonSerializable<TSelf>
{
    public static abstract IJsonSerializer<TSelf> GetSerializer();
}