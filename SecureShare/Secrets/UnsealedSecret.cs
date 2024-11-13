using System;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Secrets;

public class UnsealedSecret<TAttributes, TProtected>
    where TAttributes : IJsonSerializable<TAttributes>, IBinarySerializable<TAttributes>
    where TProtected : IBinarySerializable<TProtected>
{
    public Guid Id { get; private set; }
    public TAttributes Attributes { get; private set; }
    public TProtected Protected { get; private set; }

    public UnsealedSecret(Guid id, TAttributes attributes, TProtected @protected)
    {
        Id = id;
        Attributes = attributes;
        Protected = @protected;
    }
}

public static class UnsealedSecret
{
    public static UnsealedSecret<TAttributes, TProtected>
        Create<TAttributes, TProtected>(Guid id, TAttributes attributes, TProtected @protected)
        where TAttributes : IJsonSerializable<TAttributes>, IBinarySerializable<TAttributes>
        where TProtected : IBinarySerializable<TProtected> => new(id, attributes, @protected);
    
    public static UnsealedSecret<TAttributes, TProtected>
        Create<TAttributes, TProtected>(TAttributes attributes, TProtected @protected)
        where TAttributes : IJsonSerializable<TAttributes>, IBinarySerializable<TAttributes>
        where TProtected : IBinarySerializable<TProtected> => new(Guid.NewGuid(), attributes, @protected);
}