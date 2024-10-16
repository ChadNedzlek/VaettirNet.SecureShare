using System;
using System.Collections.Generic;
using System.Collections.Immutable;

namespace VaettirNet.SecureShare.Vaults;

public class TypedVault
{
    public Type AttributeType { get; }
    public Type ProtectedType { get; }

    public ImmutableArray<object> SealedSecrets;
    public ImmutableDictionary<Guid, ReadOnlyMemory<byte>> DeletedSecrets;

    public TypedVault(Type attributeType, Type protectedType, IEnumerable<object>? sealedSecrets = null, ImmutableDictionary<Guid, ReadOnlyMemory<byte>>? deletedSecrets = null)
    {
        AttributeType = attributeType;
        ProtectedType = protectedType;
        SealedSecrets = sealedSecrets?.ToImmutableArray() ?? [];
        DeletedSecrets = deletedSecrets ?? ImmutableDictionary<Guid, ReadOnlyMemory<byte>>.Empty;
    }
}