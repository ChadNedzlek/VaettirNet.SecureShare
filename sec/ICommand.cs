using System.Collections.Immutable;

namespace sec;

public interface ICommand<TState>
{
    int Execute(CommandSet<TState> commandSet, TState state, ICommand<TState> parent, ImmutableList<string> args);
}