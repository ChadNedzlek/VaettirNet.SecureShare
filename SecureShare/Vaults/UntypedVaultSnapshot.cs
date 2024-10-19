using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using ProtoBuf;
using VaettirNet.SecureShare.Secrets;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract(SkipConstructor = true)]
public class UntypedVaultSnapshot
{
    [ProtoMember(1)]
    public VaultIdentifier Id { get; private set; }
    [ProtoMember(2)]
    public ImmutableList<UntypedSealedSecret>? Secrets { get; private set; }
    [ProtoMember(3)]
    public ImmutableList<Signed<RemovedSecretRecord>>? RemovedSecrets { get; private set; }

    public UntypedVaultSnapshot(VaultIdentifier id, IEnumerable<UntypedSealedSecret> secrets, IEnumerable<Signed<RemovedSecretRecord>> removedSecrets)
    {
        Id = id;
        Secrets = secrets.OrderBy(s => s.Id).ToImmutableList();
        RemovedSecrets = removedSecrets.OrderBy(s => s.DangerousGetPayload().Id).ToImmutableList();
    }
}