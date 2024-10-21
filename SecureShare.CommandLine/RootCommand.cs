using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace VaettirNet.SecureShare.CommandLine;

public class RootCommand<TState> : BaseCommand<TState>
{
    protected sealed override int Execute(TState state, ICommand<TState> parent, ImmutableList<string> args)
    {
        return Execute(state, args);
    }

    protected virtual int Execute(TState state, IReadOnlyList<string> args)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Error.WriteLine($"no command: {args.FirstOrDefault()}");
        Console.ResetColor();
        return 1;
    }
}