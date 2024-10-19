using System;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Mono.Options;
using VaettirNet.Cryptography;
using VaettirNet.SecureShare.Serialization;
using VaettirNet.SecureShare.Vaults;

namespace sec;

[Command("load")]
internal class LoadCommand : BaseCommand<RunState>
{
    [Command("vault|v")]
    internal class VaultCommand : ChildCommand<RunState, LoadCommand>
    {
        protected override int Execute(RunState state, LoadCommand parent, ImmutableList<string> args)
        {
            if (args.Count == 0)
            {
                Console.Error.WriteLine("Path to load required");
                return 1;
            }

            using Stream s = File.OpenRead(args[0]);
            VaultDataSnapshot snapshot = VaultSnapshotSerializer.CreateBuilder()
                .WithSecret<LinkMetadata, LinkData>()
                .Build()
                .Deserialize(s);

            if (state.Keys != null)
            {
                state.VaultManager = VaultManager.Import(state.Algorithm, snapshot, state.Keys);
            }
            
            state.LoadedSnapshot = snapshot;

            return 0;
        }
    }
    
    [Command("keys|key|k")]
    internal class KeysCommand : ChildCommand<RunState, LoadCommand>
    {
        private string _path;
        private string _password;

        public override OptionSet GetOptions(RunState state)
        {
            return new OptionSet
            {
                {"path=", "Path to load keys from", v => _path = v},
                {"password|pw|p=", "Password, if required, to read keys", v => _password = v},
            };
        }

        protected override int Execute(RunState state, LoadCommand parent, ImmutableList<string> args)
        {
            if (_path == null && args.Count > 0)
            {
                _path = args[0];
                args = args.RemoveAt(0);
            }

            if (_path == null)
            {
                Console.Error.WriteLine("Path to load required");
                return 1;
            }

            if (state.VaultSnapshot != null)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Error.WriteLine("Unloading vault when resetting keys");
                Console.ResetColor();
            }

            state.VaultManager = null;
            state.LoadedSnapshot = null;
            
            var bytes =  File.ReadAllBytes(_path);
            Span<byte> unprotected = stackalloc byte[bytes.Length];
            ProtectedData.TryUnprotect(bytes, default, unprotected, DataProtectionScope.CurrentUser, out int cb);
            unprotected = unprotected[..cb];
            if (_password != null)
            {
                using Aes aes = Aes.Create();
                int blockBytes = aes.BlockSize / 8;
                Span<byte> key = stackalloc byte[aes.LegalKeySizes.Select(k => k.MaxSize).Max()];
                Rfc2898DeriveBytes.Pbkdf2(_password, unprotected, key, 100000, HashAlgorithmName.SHA384);
                Span<byte> decrypted = stackalloc byte[cb];
                aes.TryDecryptCbc(unprotected[blockBytes..], unprotected[..blockBytes], decrypted, out int decBytes);
                unprotected = decrypted[..decBytes];
            }

            state.Keys = ProtobufObjectSerializer<PrivateClientInfo>.Create().Deserialize(unprotected);
            return 0;
        }
    }
}