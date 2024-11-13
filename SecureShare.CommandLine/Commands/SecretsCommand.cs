using System;
using System.Collections.Immutable;
using Mono.Options;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare.CommandLine.Commands;

[Command("secrets|s")]
internal class SecretsCommand : RootCommand<RunState>
{
    [Command("list|ls|l")]
    internal class ListCommand : ChildCommand<RunState, SecretsCommand>
    {
        private bool _decrypt;

        protected override int Execute(RunState state, SecretsCommand parent, ImmutableList<string> args)
        {
            Console.WriteLine("Secrets: ");
            SecretTransformer transformer = null;
            bool decrypt = _decrypt;
            if (decrypt)
            {
                transformer = state.VaultManager.GetTransformer(state.Keys);
            }

            bool any = false;
            foreach (SealedSecret<LinkMetadata, LinkData> secret in state.Store.GetSecrets())
            {
                any = true;
                if (decrypt)
                {
                    UnsealedSecret<LinkMetadata, LinkData> unsealed = transformer.Unseal(secret);
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
            foreach (RemovedSecretRecord secret in state.Store.GetRemovedSecrets())
            {
                any = true;
                Console.WriteLine($"  id:{secret.Id} ver:{secret.Version}");
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

    [Command("add|a")]
    internal class AddSecretCommand : ChildCommand<RunState, SecretsCommand>
    {
        private string _name;

        protected override int Execute(RunState state, SecretsCommand parent, ImmutableList<string> args)
        {
            string url;
            if (_name == null)
            {
                if (args.Count >= 2)
                {
                    _name = args[0];
                    url = args[1];
                }
                else
                {
                    url = args[0];
                    _name = new Uri(url).Host;
                }
            }
            else
            {
                url = args[0];
            }

            var secret = UnsealedSecret.Create(new LinkMetadata(), new LinkData(_name, url));
            SecretTransformer transformer = state.VaultManager.GetTransformer(state.Keys);
            state.Store.GetWriter(transformer).Update(transformer.Seal(secret));
            state.VaultManager.Vault.UpdateVault(state.Store.ToSnapshot());
            return 0;
        }

        public override OptionSet GetOptions(RunState state)
        {
            return new OptionSet { { "name|n=", "name of bookmark", v => _name = v } };
        }
    }
}