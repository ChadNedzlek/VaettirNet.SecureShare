using System;
using System.Collections.Immutable;
using System.Threading.Tasks;

namespace VaettirNet.SecureShare.CommandLine;

public abstract class ChildCommand<TState, TParent> : BaseCommand<TState>, ICommand<TState, TParent> where TParent : ICommand<TState>
{
    protected sealed override Task<int> ExecuteAsync(TState state, ICommand<TState> parent, ImmutableList<string> args)
    {
        return ExecuteAsync(state, (TParent)parent, args);
    }

    protected virtual Task<int> ExecuteAsync(TState state, TParent parent, ImmutableList<string> args)
    {
        return Task.FromResult(Execute(state, parent, args));
    }

    protected virtual int Execute(TState state, TParent parent, ImmutableList<string> args)
    {
        throw new NotSupportedException("Inheritor must override one of Execute or ExecuteAsync");
    }
}