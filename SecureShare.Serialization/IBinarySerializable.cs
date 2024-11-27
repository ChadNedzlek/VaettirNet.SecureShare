namespace VaettirNet.SecureShare.Serialization;

public interface IBinarySerializable<TSelf> where TSelf : IBinarySerializable<TSelf>
{
    public static abstract IBinarySerializer<TSelf> GetBinarySerializer();
}