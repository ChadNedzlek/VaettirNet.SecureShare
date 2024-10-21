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

        public InitializeCommand(CommandPrompt prompt, VaultSnapshotSerializer vaultSerializer)
        {
            _prompt = prompt;
            _vaultSerializer = vaultSerializer;
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
                    var m = Regex.Match(_url, @"^$https://(.*?)\.([a-z0-9]*)\.digitaloceanspaces.com/(.*)$");
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

            state.Sync = new DigitalOceanSpacesSync(_bucket, _region, _name, _accessKey, _secretKey, _vaultSerializer);
            await state.Sync.UploadVaultAsync(state.Algorithm.Sign(state.VaultManager.Vault.GetSnapshot(), state.Keys), CancellationToken.None);

            return 0;
        }

        private int StoreInVault(RunState state)
        {
            if (state.VaultManager == null)
            {
                _prompt.WriteError("No vault open, use 'vault' commands to open/initialize a vault");
                return 1;
            }

            var store = state.VaultManager.Vault.GetStoreOrDefault<LinkMetadata, LinkProtected>();
            var existingValues = store.GetSecrets().ToList();
            SecretTransformer transformer = state.VaultManager.GetTransformer(state.Keys);
            if (existingValues.Count == 0)
            {
                store.UpdateSecret(transformer.Seal(UnsealedSecretValue.Create(new LinkMetadata(_accessKey, _bucket, _region, _name), new LinkProtected(_secretKey))));
            }
            else if (existingValues.Count >= 1)
            {
                if (existingValues[1].Attributes.AccessKey == _accessKey &&
                    existingValues[1].Attributes.Bucket == _bucket &&
                    existingValues[1].Attributes.Region == _region &&
                    existingValues[1].Attributes.Name == _name)
                {

                    var unsealed = transformer.Unseal(existingValues[1]);
                    if (unsealed.Protected.SecretKey == _secretKey)
                    {
                        _prompt.WriteLine("Access key already stored, no action taken");
                        return 0;
                    }

                }
                store.UpdateSecret(transformer.Seal(UnsealedSecretValue.Create(existingValues[1].Id, new LinkMetadata(_accessKey, _bucket, _region, _name), new LinkProtected(_secretKey))));
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