using System;
using System.Collections.Immutable;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare.CommandLine.Commands;

[Command("clients|c")]
internal class ClientsCommands : RootCommand<RunState>
{
    [Command("list|l")]
    internal class ListCommand : ChildCommand<RunState, ClientsCommands>
    {
        protected override int Execute(RunState state, ClientsCommands parent, ImmutableList<string> args)
        {
            Console.WriteLine("Clients:");
            foreach (VaultClientEntry client in state.LoadedSnapshot.Clients ?? [])
            {
                Console.WriteLine($"  {client.ClientId} {client.Description}");
            }

            Console.WriteLine("Blocked Clients:");
            if (state.LoadedSnapshot.BlockedClients?.IsEmpty ?? true)
            {
                Console.WriteLine("  <none>");
            }
            else
            {
                foreach (BlockedVaultClientEntry client in state.LoadedSnapshot.BlockedClients ?? [])
                {
                    Console.WriteLine($"  {client.ClientId} {client.Description}");
                }
            }

            return 0;
        }
    }
}