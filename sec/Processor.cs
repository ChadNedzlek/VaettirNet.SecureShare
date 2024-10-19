using System;
using System.Collections.Immutable;
using System.IO;
using Mono.Options;

namespace sec;

internal class Processor
{
    private readonly string[] _args;

    public Processor(string[] args)
    {
        _args = args;
    }

    public int Run()
    {
        RunState state = new();
        CommandSet<RunState> set = CommandSet<RunState>.CreateFromAssembly(GetType().Assembly);
        while (true)
        {
            WritePrompt(state);
            string line = Console.ReadLine();
            switch (line?.ToLowerInvariant())
            {
                case "q":
                case "quit":
                case "exit":
                    return 0;
            }
            var args = ArgumentSource.GetArguments(new StringReader(line)).ToImmutableList();
            set.RootCommand.Execute(set, state, null, args);
        }
    }

    private void WritePrompt(RunState state)
    {
        Console.Write($"{(state.Keys == null ? 'N' : 'K')} {(state.VaultManager == null ? 'N' : 'V')} [{state.Store?.Id.Name}]> ");
    }
}