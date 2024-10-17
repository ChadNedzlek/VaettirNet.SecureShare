using System.Collections.Immutable;
using ProtoBuf;
using VaettirNet.SecureShare.Secrets;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract]
public class UntypedVaultSnapshot
{
    [ProtoMember(1)]
    public required ImmutableList<UntypedSealedValue> Secrets { get; init; }
    [ProtoMember(2)]
    public required ImmutableList<Signed<RemovedSecretRecord>> RemovedSecrets { get; init; }
}