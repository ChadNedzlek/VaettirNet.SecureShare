using System;
using System.Collections.Immutable;

namespace SecureShare;

public record VaultClientEntry(
    Guid ClientId,
    string Description,
    ImmutableArray<byte> PublicKey,
    ImmutableArray<byte> EncryptedSharedKey,
    Guid AuthorizedByClientId);