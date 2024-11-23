using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.CommandLine;

[PackedBinarySerializable]
public class LinkData : BinarySerializable<LinkData>
{
    [PackedBinaryMember(1)]
    public string Name { get; private set; }
    [PackedBinaryMember(2)]
    public string Url { get; private set; }

    public LinkData(string name, string url)
    {
        Name = name;
        Url = url;
    }
}