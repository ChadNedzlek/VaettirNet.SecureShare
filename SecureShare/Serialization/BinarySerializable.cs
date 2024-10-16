namespace VaettirNet.SecureShare.Serialization;

public abstract class BinarySerializable<TSelf> : IBinarySerializable<TSelf> where TSelf : BinarySerializable<TSelf>
{
    public static IBinarySerializer<TSelf> GetBinarySerializer() => ProtobufObjectSerializer<TSelf>.Create();
}