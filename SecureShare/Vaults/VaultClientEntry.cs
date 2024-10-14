using System;
using System.Collections.Immutable;

namespace VaettirNet.SecureShare.Vaults;

public record VaultClientEntry(
    Guid ClientId,
    string Description,
    ReadOnlyMemory<byte> PublicKey,
    ReadOnlyMemory<byte> EncryptedSharedKey,
    Guid AuthorizedByClientId);