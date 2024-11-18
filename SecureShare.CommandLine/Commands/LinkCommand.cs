using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Mono.Options;
using ProtoBuf;
using VaettirNet.SecureShare.CommandLine.Services;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Serialization;
using VaettirNet.SecureShare.Sync;
using VaettirNet.SecureShare.Vaults;
using VaettirNet.SecureShare.Vaults.Conflict;

namespace VaettirNet.SecureShare.CommandLine.Commands;

[Command("link")]
internal class LinkCommand : RootCommand<RunState>
{
    [Command("initialize|init|i")]
    internal class InitializeCommand : ChildCommand<RunState, LinkCommand>
    {
        private bool _storeInVault;
        private string _filePath;
        private string _filePassword;
        private string _accessKey;
        private string _secretKey;
        private string _url;
        private string _bucket;
        private string _name;
        private string _region;

        private readonly CommandPrompt _prompt;
        private readonly VaultSnapshotSerializer _vaultSerializer;
        private readonly VaultConflictResolver _conflictResolver;

        public InitializeCommand(CommandPrompt prompt, VaultSnapshotSerializer vaultSerializer, VaultConflictResolver conflictResolver)
        {
            _prompt = prompt;
            _vaultSerializer = vaultSerializer;
            _conflictResolver = conflictResolver;
        }

        protected override async Task<int> ExecuteAsync(RunState state, LinkCommand parent, ImmutableList<string> args)
        {
            if (_url == null)
            {
                _url = $"https://{_bucket}.{_region}.digitaloceanspaces.com/{_name}";
            }
            else
            {
                if (_name == null || _bucket == null)
                {
                    Match m = Regex.Match(_url, @"^$https://(.*?)\.([a-z0-9]*)\.digitaloceanspaces.com/(.*)$");
                    if (m.Success)
                    {
                        _bucket = m.Groups[1].Value;
                        _region = m.Groups[2].Value;
                        _name = m.Groups[3].Value;
                    }
                    else
                    {
                        _prompt.WriteError("Unexpected URL, should be 'https://{bucket}.{region}.digitaloceanspaces.com/{name}");
                        return 1;
                    }
                }
            }

            if (_storeInVault)
            {
                int res = StoreInVault(state);
                if (res != 0)
                {
                    return res;
                }
            }

            state.Sync = new DigitalOceanSpacesSync(new DigitalOceanConfig(_bucket, _region, _name, _accessKey, _secretKey), _vaultSerializer);
            ValidatedVaultDataSnapshot vaultDataSnapshot = state.VaultManager.Vault.GetSnapshot(new RefSigner(state.Algorithm, state.Keys));
            return await PutVault(state, vaultDataSnapshot);
        }

        private async Task<int> PutVault(RunState state, ValidatedVaultDataSnapshot vaultDataSnapshot)
        {
            while (true)
            {
                PutVaultResult result = await state.Sync.PutVaultAsync(vaultDataSnapshot, cancellationToken: CancellationToken.None);
                if (result.Succeeded)
                {
                    _prompt.WriteLine("Vault uploaded");
                    state.LoadedSnapshot = vaultDataSnapshot;
                    return 0;
                }

                if (result.InvalidExistingVault is { } invalidVaultException)
                {
                    _prompt.WriteWarning($"Current vault is invalid: {invalidVaultException.Message}");
                    if (!_prompt.Confirm("Discard remote (invalid) changes and replace with local version? "))
                    {
                        _prompt.WriteLine("Aborting");
                        return 2;
                    }

                    PutVaultResult putVaultResult = await state.Sync.PutVaultAsync(vaultDataSnapshot, cancellationToken: CancellationToken.None);
                    if (!putVaultResult.Succeeded)
                    {
                        _prompt.WriteError("Failed to upload vault");
                        return 1;
                    }

                    _prompt.WriteLine("Vault overwritten");
                    return 0;
                }

                if (result.ConflictVault is { } signedConflictingSnapshot)
                {
                    var validatedConflict = signedConflictingSnapshot.Validate(state.Algorithm);
                    _prompt.WriteWarning("Conflict detected during vault upload...");
                    if (!validatedConflict.TryGetSignerPublicInfo(out PublicClientInfo signer))
                    {
                        _prompt.WriteError("No trusted signer found");
                        if (!_prompt.Confirm("Discard remote (unsigned) changes and replace with local version? "))
                        {
                            _prompt.WriteLine("Aborting, local vault is unsynced");
                            return 2;
                        }

                        if ((await state.Sync.PutVaultAsync(validatedConflict, force: true, cancellationToken: CancellationToken.None)).Succeeded)
                        {
                            _prompt.WriteError("Failed to upload vault");
                            return 1;
                        }

                        state.LoadedSnapshot = vaultDataSnapshot;
                    }

                    if (!ValidatedVaultDataSnapshot.TryValidate(
                            signedConflictingSnapshot,
                            signer.SigningKey.Span,
                            state.Algorithm,
                            out var conflictingSnapshot
                        ))
                    {
                        _prompt.WriteError("Invalid signature found");
                        if (!_prompt.Confirm("Discard remote (invalid) changes and replace with local version?"))
                        {
                            _prompt.WriteLine("Aborting, local vault is unsynced");
                            return 2;
                        }

                        if ((await state.Sync.PutVaultAsync(validatedConflict, force: true, cancellationToken: CancellationToken.None)).Succeeded)
                        {
                            _prompt.WriteError("Failed to upload vault");
                            return 1;
                        }
                    }

                    VaultConflictResult conflictResult = _conflictResolver.Resolve(state.LoadedSnapshot, conflictingSnapshot, vaultDataSnapshot);
                    if (_conflictResolver.TryAutoResolveConflicts(conflictResult, state.Signer, out var newSnapshot))
                    {
                        if (_prompt.Confirm("Auto-resolve possible. Auto-resolve?"))
                        {
                            var conflictUploadResult = await state.Sync.PutVaultAsync(newSnapshot, etag: result.CacheKey);
                            if (conflictUploadResult.Succeeded)
                            {
                                return 0;
                            }
                            _prompt.WriteWarning("Failed to resolve conflict... retrying...");
                            continue;
                        }
                    }

                    PartialVaultConflictResolution resolution = conflictResult.GetResolver().WithAutoResolutions();
                    while (resolution.TryGetNextUnresolved(out var conflict))
                    {
                        switch (conflict)
                        {
                            case ClientConflictItem clientConflictItem:
                                _prompt.WriteLine($"Conflict in client '{clientConflictItem.Description}' ({clientConflictItem.Id})");
                                DisplayClient("Original", clientConflictItem.BaseEntry);
                                DisplayClient("Remote", clientConflictItem.Remote);
                                DisplayClient("Local", clientConflictItem.Local);

                                switch (Resolve())
                                {
                                    case 'l':
                                        resolution.WithResolution(conflict, VaultResolutionItem.AcceptLocal);
                                        break;
                                    case 'r':
                                        resolution.WithResolution(conflict, VaultResolutionItem.AcceptRemote);
                                        break;
                                    case 'a':
                                        _prompt.WriteWarning("Aborting resolve.");
                                        return 1;
                                }

                                break;

                                void DisplayClient(string name, OneOf<VaultClientEntry, BlockedVaultClientEntry> entry)
                                {
                                    entry.Map(
                                        client =>
                                        {
                                            if (client is null)
                                            {
                                                _prompt.WriteLine("  {name}: <none>");
                                            }
                                            else
                                            {
                                                _prompt.WriteLine(
                                                    $"""
                                                      {name}: '{client.Description}'
                                                        Id: {client.ClientId}
                                                        Keys:{Convert.ToBase64String(client.SigningKey.Span)}
                                                        Authorized: {(client.Authorizer == state.Keys.ClientId ? "this client" : client.Authorizer)}
                                                    """
                                                );
                                            }
                                        },
                                        removed => _prompt.WriteWarning(
                                            $"""
                                              {name} BLOCKED: '{removed.Description}'
                                                Id: {removed.ClientId}
                                                Keys:{Convert.ToBase64String(removed.PublicKey.Span)}
                                            """
                                        )
                                    );
                                }
                            case SecretConflictItem secretConflictItem:
                                break;
                            case VaultListConflictItem listItem: break;
                        }
                    }

                    char Resolve()
                    {
                        while (true)
                        {
                            switch (_prompt.Prompt("Accept [l]ocal or [r]emote (or [a]bort)? ").ToLowerInvariant())
                            {
                                case "local":
                                case "l":
                                    return 'l';
                                case "remote":
                                case "r":
                                    return 'r';
                                case "abort":
                                case "a":
                                    return 'a';
                                default:
                                    _prompt.WriteError("Invalid response");
                                    break;
                            }
                        }
                    }
                }
            }
        }

        private int StoreInVault(RunState state)
        {
            if (state.VaultManager == null)
            {
                _prompt.WriteError("No vault open, use 'vault' commands to open/initialize a vault");
                return 1;
            }

            OpenVaultReader<LinkMetadata, LinkProtected> store = state.VaultManager.Vault.GetStoreOrDefault<LinkMetadata, LinkProtected>();
            SecretTransformer transformer = state.VaultManager.GetTransformer(state.Keys);
            var writer = store.GetWriter(transformer);
            List<SealedSecret<LinkMetadata, LinkProtected>> existingValues = store.GetSecrets().ToList();
            if (existingValues.Count == 0)
            {
                writer.Update(transformer.Seal(UnsealedSecret.Create(new LinkMetadata(_accessKey, _bucket, _region, _name), new LinkProtected(_secretKey))));
            }
            else if (existingValues.Count >= 1)
            {
                if (existingValues[1].Attributes.AccessKey == _accessKey &&
                    existingValues[1].Attributes.Bucket == _bucket &&
                    existingValues[1].Attributes.Region == _region &&
                    existingValues[1].Attributes.Name == _name)
                {

                    UnsealedSecret<LinkMetadata, LinkProtected> unsealed = transformer.Unseal(existingValues[1]);
                    if (unsealed.Protected.SecretKey == _secretKey)
                    {
                        _prompt.WriteLine("Access key already stored, no action taken");
                        return 0;
                    }

                }
                writer.Update(transformer.Seal(UnsealedSecret.Create(existingValues[1].Id, new LinkMetadata(_accessKey, _bucket, _region, _name), new LinkProtected(_secretKey))));
            }
            
            state.VaultManager.Vault.UpdateVault(store.ToSnapshot());
            return 0;
        }

        public override OptionSet GetOptions(RunState state)
        {
            return new OptionSet
            {
                {"access-key|ak|a=", "Digital Ocean Spaces Access Key", v => _accessKey = v},
                {"secret-key|sk|s=", "Digital Ocean Spaces Secret Key", v => _secretKey = v},
                {"url|u=", "Target URL", v => _url = v},
                {"store-in-vault|vault|v", "Store the credentials in the currently open vault", v => _storeInVault = v is not null},
                {"output|file|o=", "Store the credentials in target file", v => _filePath = v},
                {"password|pw|p=", "File store password", v => _filePassword = v},
                {"bucket-name|bucket|bn|b=", "Bucket name", v => _bucket = v},
                {"name|n=", "Storage name", v => _name = v},
                {"region|r=", "Spaces region name (default sfo3", v => _region = v},
            };
        }
    }

    [ProtoContract(SkipConstructor = true)]
    public class LinkMetadata : FullSerializable<LinkMetadata>
    {
        [ProtoMember(1)]
        public string AccessKey { get; private set; }
        [ProtoMember(2)]
        public string Bucket { get; private set; }
        [ProtoMember(3)]
        public string Region { get; private set; }
        [ProtoMember(4)]
        public string Name { get; private set; }

        public LinkMetadata(string accessKey, string bucket, string region, string name)
        {
            AccessKey = accessKey;
            Bucket = bucket;
            Region = region;
            Name = name;
        }
    }

    [ProtoContract(SkipConstructor = true)]
    public class LinkProtected : BinarySerializable<LinkProtected>
    {
        [ProtoMember(1)]
        public string SecretKey { get; private set; }
            
        public LinkProtected(string secretKey)
        {
            SecretKey = secretKey;
        }
    }
}