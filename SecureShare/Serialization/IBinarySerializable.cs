using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using ProtoBuf;

namespace VaettirNet.SecureShare.Serialization;

public interface IBinarySerializable<TSelf> where TSelf : IBinarySerializable<TSelf>
{
    public static abstract IBinarySerializer<TSelf> GetBinarySerializer();
}