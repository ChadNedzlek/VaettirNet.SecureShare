namespace sec;

internal static class Program
{
    static int Main(string[] args)
    {
        return new Processor(args).Run();
    }
}

public interface ICommand<TState, TParent> : ICommand<TState>
    where TParent : ICommand<TState>
{
}