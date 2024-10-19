using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Mono.Options;

namespace sec;

public abstract class BaseCommand<TState> : ICommand<TState>
{
    public int Execute(CommandSet<TState> commandSet, TState state, ICommand<TState> parent, ImmutableList<string> args)
    {
        OptionSet optionSet = GetOptions(state);
        List<string> rem = optionSet.Parse(args);
        if (rem.Count > 0)
        {
            var child = commandSet.GetChildCommand(GetType(), rem[0]);
            if (child == null && parent == null)
            {
                child = commandSet.GetChildCommand(null, rem[0]);
            }

            if (child != null)
            {
                rem.RemoveAt(0);
                return child.Execute(commandSet, state, this, rem.ToImmutableList());
            }
        }

        return Execute(state, parent, rem.ToImmutableList());
    }

    protected virtual int Execute(TState state, ICommand<TState> parent, ImmutableList<string> args)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Error.WriteLine($"no command '{args.FirstOrDefault()}'");
        Console.ResetColor();
        return 1;
    }

    public virtual OptionSet GetOptions(TState state) => new();
}