using System;
using System.Collections.Immutable;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Mono.Options;
using VaettirNet.SecureShare.CommandLine.Commands;
using VaettirNet.SecureShare.CommandLine.Services;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare.CommandLine;

internal class Processor
{
    private readonly string[] _args;

    public Processor(string[] args)
    {
        _args = args;
    }

    public async Task<int> Run()
    {
        ServiceCollection collection = new();
        collection.AddSingleton<CommandPrompt>();
        collection.AddSingleton(
            VaultSnapshotSerializer.CreateBuilder()
                .WithSecret<LinkMetadata, LinkData>()
                .WithSecret<LinkCommand.LinkMetadata, LinkCommand.LinkProtected>()
                .Build()
        );
        using ServiceProvider services = collection.BuildServiceProvider();
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
            using IServiceScope scope = services.CreateScope();
            ICommandSet<RunState> scopedSet = set.GetScoped(scope);
            await scopedSet.RootCommand.ExecuteAsync(scopedSet, state, null, args);
        }
    }

    private void WritePrompt(RunState state)
    {
        Console.Write($"{(state.Keys == null ? 'N' : 'K')} {(state.VaultManager == null ? 'N' : 'V')} [{state.Store?.Id.Name}]> ");
    }
}