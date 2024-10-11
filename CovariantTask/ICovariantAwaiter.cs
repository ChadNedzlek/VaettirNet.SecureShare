using System.Runtime.CompilerServices;

namespace VaettirNet.Threading.Tasks;

public interface ICovariantAwaiter<out TResult> : INotifyCompletion
{
    bool IsCompleted { get; }
    TResult GetResult();
}