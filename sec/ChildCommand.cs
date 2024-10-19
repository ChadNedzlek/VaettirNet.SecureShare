using System.Collections.Immutable;

namespace sec;

public abstract class ChildCommand<TState, TParent> : BaseCommand<TState>, ICommand<TState, TParent> where TParent : ICommand<TState>
{
    protected override int Execute(TState state, ICommand<TState> parent, ImmutableList<string> args)
    {
        return Execute(state, (TParent)parent, args);
    }

    protected abstract int Execute(TState state, TParent parent, ImmutableList<string> args);
}