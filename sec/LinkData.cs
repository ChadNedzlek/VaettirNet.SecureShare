using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace sec;

[ProtoContract(SkipConstructor = true)]
public class LinkData : BinarySerializable<LinkData>
{
    [ProtoMember(1)]
    public string Name { get; private set; }
    [ProtoMember(2)]
    public string Url { get; private set; }

    public LinkData(string name, string url)
    {
        Name = name;
        Url = url;
    }
}