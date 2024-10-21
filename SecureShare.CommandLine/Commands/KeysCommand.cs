using System;
using System.Buffers;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Mono.Options;
using VaettirNet.Cryptography;
using VaettirNet.SecureShare.Serialization;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare.CommandLine.Commands;

[Command("keys|key|k")]
internal class KeysCommand : BaseCommand<RunState>
{
    [Command("initialize|init|i")]
    internal class InitializeCommand : ChildCommand<RunState, KeysCommand>
    {
        protected override int Execute(RunState state, KeysCommand parent, ImmutableList<string> args)
        {
            state.Algorithm.Create(Guid.NewGuid(), out var keys, out _);
            state.Keys = keys;
            return 0;
        }
    }
    
    [Command("load|l")]
    internal class LoadCommand : ChildCommand<RunState, KeysCommand>
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

        protected override int Execute(RunState state, KeysCommand parent, ImmutableList<string> args)
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
    [Command("save|s")]
    internal class SaveCommand : ChildCommand<RunState, KeysCommand>
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

        protected override int Execute(RunState state, KeysCommand parent, ImmutableList<string> args)
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
    
}