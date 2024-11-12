using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading.Tasks;
using Mono.Options;

namespace VaettirNet.SecureShare.CommandLine;

public abstract class BaseCommand<TState> : ICommand<TState>
{
    protected virtual int Execute(TState state, ICommand<TState> parent, ImmutableList<string> args)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Error.WriteLine($"no command '{args.FirstOrDefault()}'");
        Console.ResetColor();
        return 1;
    }

    public virtual OptionSet GetOptions(TState state) => new();
    
    public virtual Task<int> ExecuteAsync(ICommandSet<TState> commandSet, TState state, ICommand<TState> parent, ImmutableList<string> args)
    {
        OptionSet optionSet = GetOptions(state);
        List<string> rem = optionSet.Parse(args);
        if (rem.Count > 0)
        {
            ICommand<TState> child = commandSet.GetChildCommand(GetType(), rem[0]);
            if (child == null && parent == null)
            {
                child = commandSet.GetChildCommand(null, rem[0]);
            }

            if (child != null)
            {
                rem.RemoveAt(0);
                return child.ExecuteAsync(commandSet, state, this, rem.ToImmutableList());
            }
        }

        return ExecuteAsync(state, parent, rem.ToImmutableList());
    }

    protected virtual Task<int> ExecuteAsync(TState state, ICommand<TState> parent, ImmutableList<string> args)
    {
        return Task.FromResult(Execute(state, parent, args));
    }
}