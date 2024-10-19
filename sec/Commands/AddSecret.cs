using System;
using System.Collections.Immutable;
using Mono.Options;
using VaettirNet.SecureShare.Secrets;

namespace sec;

[Command("add|a")]
internal class AddSecretCommand : BaseCommand<RunState>
{
    private string _name;
    protected override int Execute(RunState state, ICommand<RunState> parent, ImmutableList<string> args)
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

        var secret = UnsealedSecretValue.Create(new LinkMetadata(), new LinkData(_name, url));
        SecretTransformer transformer = state.VaultManager.GetTransformer(state.Keys);
        state.Store.UpdateSecret(transformer.Seal(secret));
        state.VaultManager.Vault.UpdateVault(state.Store.ToSnapshot());
        return 0;
    }

    public override OptionSet GetOptions(RunState state)
    {
        return new OptionSet { {"name|n=", "name of bookmark", v => _name = v } };
    }
}