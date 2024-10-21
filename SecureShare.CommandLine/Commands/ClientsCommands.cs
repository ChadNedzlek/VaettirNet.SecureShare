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
            foreach (VaultClientEntry client in state.VaultSnapshot.Clients)
            {
                Console.WriteLine($"  {client.ClientId} {client.Description}");
            }

            Console.WriteLine("Blocked Clients:");
            if (state.VaultSnapshot.BlockedClients.IsEmpty)
            {
                Console.WriteLine("  <none>");
            }
            else
            {
                foreach (VaultClientEntry client in state.VaultSnapshot.Clients)
                {
                    Console.WriteLine($"  {client.ClientId} {client.Description}");
                }
            }

            return 0;
        }
    }
}