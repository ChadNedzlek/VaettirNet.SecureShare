using System;
using System.Threading.Tasks;

namespace VaettirNet.Threading.Tasks;

internal class CompletedCovariantTask<T>(T value) : ICovariantTask<T>
{
    public ICovariantAwaiter<T> GetAwaiter() => new AwaitWrapper(value);
    Task ICovariantTask<T>.AsTaskBase() => Task.FromResult(value);

    private class AwaitWrapper(T value) : ICovariantAwaiter<T>
    {
        public bool IsCompleted => true;
        public T GetResult() => value;
        public void OnCompleted(Action completion) => completion();
    }
}