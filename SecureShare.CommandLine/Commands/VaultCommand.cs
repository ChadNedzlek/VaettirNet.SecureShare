using System;
using System.Collections.Immutable;
using System.IO;
using VaettirNet.SecureShare.CommandLine.Services;
using VaettirNet.SecureShare.Crypto;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare.CommandLine.Commands;

[Command("vault|v")]
internal class VaultCommand : BaseCommand<RunState>
{
    [Command("initialize|init|i")]
    internal class InitializeCommand : ChildCommand<RunState, VaultCommand>
    {
        protected override int Execute(RunState state, VaultCommand parent, ImmutableList<string> args)
        {
            if (state.Keys != null)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Error.WriteLine("Overwriting existing keys with new keys from initialized vault");
                Console.ResetColor();
            }

            VaultManager manager = VaultManager.Initialize(args.Count > 0 ? args[0] : "vault", state.Algorithm, out PrivateKeyInfo keys);
            state.Keys = keys;
            state.LoadedSnapshot = manager.Vault.GetSnapshot(new RefSigner(state.Algorithm, keys));
            state.VaultManager = manager;
            return 0;
        }
    }

    [Command("list|ls|l")]
    internal class VaultsCommand : ChildCommand<RunState, VaultCommand>
    {
        private readonly CommandPrompt _prompt;

        public VaultsCommand(CommandPrompt prompt)
        {
            _prompt = prompt;
        }

        protected override int Execute(RunState state, VaultCommand parent, ImmutableList<string> args)
        {
            _prompt.WriteLine("Vaults:");
            if (state.LoadedSnapshot.Vaults?.IsEmpty ?? true)
                _prompt.WriteLine("  <none>", ConsoleColor.DarkGray);
            else
                foreach (UntypedVaultSnapshot vault in state.LoadedSnapshot.Vaults ?? [])
                    _prompt.WriteLine($"  {vault.Id.Name}");

            return 0;
        }
    }

    [Command("load")]
    internal class LoadCommand : ChildCommand<RunState, VaultCommand>
    {
        private readonly CommandPrompt _prompt;

        public LoadCommand(CommandPrompt prompt)
        {
            _prompt = prompt;
        }

        protected override int Execute(RunState state, VaultCommand parent, ImmutableList<string> args)
        {
            if (args.Count == 0)
            {
                _prompt.WriteError("Path to load required");
                return 1;
            }

            using Stream stream = File.OpenRead(args[0]);
            Signed<UnvalidatedVaultDataSnapshot> signedSnapshot = VaultSnapshotSerializer.CreateBuilder()
                .WithSecret<LinkMetadata, LinkData>()
                .Build()
                .Deserialize(stream);


            if (!signedSnapshot.TryValidate(state.Algorithm, out ValidatedVaultDataSnapshot snapshot))
            {
                _prompt.WriteError("Vault signature does not match");
                return 2;
            }

            if (state.Keys != null) state.VaultManager = VaultManager.Import(state.Algorithm, snapshot, state.Keys);

            state.LoadedSnapshot = snapshot;
            return 0;
        }
    }

    [Command("save")]
    internal class SaveCommand : ChildCommand<RunState, VaultCommand>
    {
        protected override int Execute(RunState state, VaultCommand parent, ImmutableList<string> args)
        {
            if (args.Count == 0)
            {
                Console.Error.WriteLine("Path to load required");
                return 1;
            }

            using Stream stream = File.Create(args[0]);
            VaultSnapshotSerializer.CreateBuilder()
                .WithSecret<LinkMetadata, LinkData>()
                .Build()
                .Serialize(stream, state.VaultManager.Vault.GetSnapshot(new RefSigner(state.Algorithm, state.Keys)));

            return 0;
        }
    }

    [Command("select|s")]
    internal class SelectCommand : ChildCommand<RunState, VaultCommand>
    {
        protected override int Execute(RunState state, VaultCommand parent, ImmutableList<string> args)
        {
            if (state.Store != null)
            {
                Console.WriteLine($"Saving previous vault {state.Store.Id.Name}");
                state.VaultManager.Vault.UpdateVault(state.Store.ToSnapshot());
            }

            state.Store = state.VaultManager.Vault.GetStoreOrDefault<LinkMetadata, LinkData>(args.Count == 0 ? null : args[0]);
            return 0;
        }
    }
}