using System;
using System.Buffers;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Mono.Options;
using VaettirNet.Cryptography;
using VaettirNet.SecureShare;
using VaettirNet.SecureShare.Serialization;
using VaettirNet.SecureShare.Vaults;

namespace sec;

[Command("save")]
internal class SaveCommand : BaseCommand<RunState>
{
    [Command("keys|key|k")]
    internal class KeysCommand : ChildCommand<RunState, SaveCommand>
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

        protected override int Execute(RunState state, SaveCommand parent, ImmutableList<string> args)
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

            var serializer = ProtobufObjectSerializer<PrivateClientInfo>.Create();
            using RentedSpan<byte> unprotected = SpanHelpers.GrowingSpan(
                stackalloc byte[200],
                (Span<byte> span, out int cb) => serializer.TrySerialize(state.Keys, span, out cb),
                ArrayPool<byte>.Shared
            );
            using var bytes = SpanHelpers.GrowingSpan(
                stackalloc byte[unprotected.Span.Length * 2],
                unprotected.Span,
                (Span<byte> span, Span<byte> unprot, out int cbProtected) =>
                    ProtectedData.TryProtect(unprot, default, span, DataProtectionScope.CurrentUser, out cbProtected),
                ArrayPool<byte>.Shared
            );

            var output = bytes.Span;
            
            if (_password != null)
            {
                using Aes aes = Aes.Create();
                int blockBytes = aes.BlockSize / 8;
                Span<byte> key = stackalloc byte[aes.LegalKeySizes.Select(k => k.MaxSize).Max()];
                Rfc2898DeriveBytes.Pbkdf2(_password, unprotected.Span, key, 100000, HashAlgorithmName.SHA384);
                Span<byte> encrypted = stackalloc byte[bytes.Span.Length + blockBytes];
                Span<byte> iv = encrypted[..blockBytes];
                RandomNumberGenerator.Fill(iv);
                Span<byte> cipherText = encrypted[blockBytes..];
                aes.TryEncryptCbc(bytes.Span, iv, cipherText, out int cb);
                output = encrypted[..cb];
            }

            File.WriteAllBytes(_path, output);
            return 0;
        }
    }
    
    [Command("vault|v")]
    internal class VaultCommand : ChildCommand<RunState, SaveCommand>
    {
        protected override int Execute(RunState state, SaveCommand parent, ImmutableList<string> args)
        {
            if (args.Count == 0)
            {
                Console.Error.WriteLine("Path to load required");
                return 1;
            }

            using (Stream s = File.Create(args[0]))
            {
                VaultSnapshotSerializer.CreateBuilder()
                    .WithSecret<LinkMetadata, LinkData>()
                    .Build()
                    .Serialize(s, state.VaultManager.Vault.GetSnapshot());
            }
            using (Stream s = File.OpenRead(args[0]))
            {
                var snappy = VaultSnapshotSerializer.CreateBuilder()
                    .WithSecret<LinkMetadata, LinkData>()
                    .Build()
                    .Deserialize(s);
            }

            return 0;
        }
    }
}