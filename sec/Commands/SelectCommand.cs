using System;
using System.Collections.Immutable;

namespace sec;

[Command("select|s")]
internal class SelectCommand : BaseCommand<RunState>
{
    protected override int Execute(RunState state, ICommand<RunState> parent, ImmutableList<string> args)
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