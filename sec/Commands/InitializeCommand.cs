using System;
using System.Collections.Immutable;
using VaettirNet.SecureShare.Vaults;

namespace sec;

[Command("initialize|init|i")]
internal class InitializeCommand : BaseCommand<RunState>
{
    [Command("keys|key|k")]
    internal class KeysCommand : ChildCommand<RunState, InitializeCommand>
    {
        protected override int Execute(RunState state, InitializeCommand parent, ImmutableList<string> args)
        {
            state.Algorithm.Create(Guid.NewGuid(), out var keys, out _);
            state.Keys = keys;
            return 0;
        }
    }
    
    [Command("vault|v")]
    internal class VaultCommand : ChildCommand<RunState, InitializeCommand>
    {
        protected override int Execute(RunState state, InitializeCommand parent, ImmutableList<string> args)
        {
            if (state.Keys != null)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Error.WriteLine("Overwriting existing keys with new keys from initialized vault");
                Console.ResetColor();
            }

            VaultManager manager = VaultManager.Initialize(args.Count > 0 ? args[0] : "vault", state.Algorithm, out PrivateClientInfo keys);
            state.Keys = keys;
            state.LoadedSnapshot = manager.Vault.GetSnapshot();
            state.VaultManager = manager;
            return 0;
        }
    }
}