using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using Mono.Options;
using VaettirNet.SecureShare;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Vaults;

namespace sec;

[Command("list|l")]
internal class ListCommand : RootCommand<RunState>
{
    protected override int Execute(RunState state, IReadOnlyList<string> args)
    {
        Console.WriteLine("Vaults:");
        if (state.VaultSnapshot.Vaults.IsEmpty)
        {
            Console.WriteLine("  <none>");
        }
        else
        {
            foreach (UntypedVaultSnapshot vault in state.VaultSnapshot.Vaults)
            {
                Console.WriteLine($"  {vault.Id.Name}");
            }
        }
        return 0;
    }

    [Command("vaults|v")]
    internal class VaultsCommand : ChildCommand<RunState, ListCommand>
    {
        protected override int Execute(RunState state, ListCommand parent, ImmutableList<string> args)
        {
            return parent.Execute(state, args);
        }
    }
    
    [Command("clients|c")]
    internal class ClientsCommands : ChildCommand<RunState, ListCommand>
    {
        protected override int Execute(RunState state, ListCommand parent, ImmutableList<string> args)
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

    [Command("secrets|s")]
    internal class SecretsCommand : ChildCommand<RunState, ListCommand>
    {
        private bool _decrypt = false;
        protected override int Execute(RunState state, ListCommand parent, ImmutableList<string> args)
        {
            Console.WriteLine("Secrets: ");
            SecretTransformer transformer = null;
            bool decrypt = _decrypt;
            if (decrypt)
            {
                transformer = state.VaultManager.GetTransformer(state.Keys);
            }

            bool any = false;
            foreach (SealedSecretSecret<LinkMetadata, LinkData> secret in state.Store.GetSecrets())
            {
                any = true;
                if (decrypt)
                {
                    var unsealed = transformer.Unseal(secret);
                    Console.WriteLine(
                        $"""
                          {unsealed.Protected.Name}
                            {unsealed.Protected.Url}
                            id:{secret.Id}
                            created:{secret.Attributes.Created:g}
                            ver:{secret.Version}
                        """
                    );
                }
                else
                {
                    Console.WriteLine($"  id:{secret.Id} created:{secret.Attributes.Created:g} ver:{secret.Version}");
                }
            }

            if (!any)
            {
                Console.WriteLine("  <none>");
            }

            Console.WriteLine("Removed: ");
            any = false;
            foreach (Signed<RemovedSecretRecord> secret in state.Store.GetRemovedSecrets())
            {
                any = true;
                RemovedSecretRecord payload = secret.DangerousGetPayload();
                Console.WriteLine($"  id:{payload.Id} ver:{payload.Version} by:{secret.Signer}");
            }
            if (!any)
            {
                Console.WriteLine("  <none>");
            }

            return 0;
        }

        public override OptionSet GetOptions(RunState state)
        {
            return new OptionSet { { "decrypt|d", "Include decrypted values", v => _decrypt = v is not null }, };
        }
    }
}