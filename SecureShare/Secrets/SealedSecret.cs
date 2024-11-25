using System;
using System.Collections;
using System.Collections.Generic;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Secrets;

[PackedBinarySerializable(IncludeNonPublic = true)]
public class SealedSecret<TAttributes, TProtected> : UntypedSealedSecret
    where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
    where TProtected : IBinarySerializable<TProtected>
{
    [PackedBinaryMember(2)]
    public TAttributes Attributes { get; private set; }

    [PackedBinaryMember(3)]
    public ReadOnlyMemory<byte> Protected { get; private set; }

    [PackedBinaryMember(4)]
    public int KeyId { get; private set; }

    public SealedSecret(Guid id, uint version, ReadOnlyMemory<byte> hashBytes, TAttributes attributes, ReadOnlyMemory<byte> @protected, int keyId) : base(id, version, hashBytes)
    {
        Attributes = attributes;
        Protected = @protected;
        KeyId = keyId;
    }

    public SealedSecret<TAttributes, TProtected> WithVersion(uint version) => new(Id, version, HashBytes, Attributes, Protected, KeyId);

    public new class Comparer : IComparer<SealedSecret<TAttributes, TProtected>>, IComparer
    {
        private static readonly Comparer<Guid?> s_comparer = Comparer<Guid?>.Default;
        public static Comparer Instance { get; } = new();

        public int Compare(SealedSecret<TAttributes, TProtected>? x, SealedSecret<TAttributes, TProtected>? y) => s_comparer.Compare(x?.Id, y?.Id);
        public int Compare(object? x, object? y) => s_comparer.Compare((x as SealedSecret<TAttributes, TProtected>)?.Id, (y as SealedSecret<TAttributes, TProtected>)?.Id);
    }
}

public static class SealedSecret
{
    public static SealedSecret<TAttributes, TProtected> Create<TAttributes, TProtected>(
        Guid id,
        TAttributes attributes,
        ReadOnlyMemory<byte> @protected,
        int keyId,
        ReadOnlyMemory<byte> hashBytes,
        uint version = 0
    )
        where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
        where TProtected : IBinarySerializable<TProtected> => new(id, version, hashBytes, attributes, @protected, keyId);
}