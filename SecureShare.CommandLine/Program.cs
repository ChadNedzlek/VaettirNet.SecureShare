using System.Threading.Tasks;

namespace VaettirNet.SecureShare.CommandLine;

internal static class Program
{
    private static Task<int> Main(string[] args)
    {
        return new Processor(args).Run();
    }
}

public interface ICommand<TState, TParent> : ICommand<TState>
    where TParent : ICommand<TState>
{
}