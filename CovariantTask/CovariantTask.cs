using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace VaettirNet.Threading.Tasks;

internal class CovariantTask<T>(Task<T> task) : ICovariantTask<T>
{
    public ICovariantAwaiter<T> GetAwaiter()
    {
        return new AwaitWrapper(task.GetAwaiter());
    }

    Task ICovariantTask<T>.AsTaskBase()
    {
        return task;
    }

    public static implicit operator CovariantTask<T>(Task<T> t)
    {
        return new CovariantTask<T>(t);
    }

    private class AwaitWrapper(TaskAwaiter<T> task) : ICovariantAwaiter<T>
    {
        public bool IsCompleted => task.IsCompleted;

        public T GetResult()
        {
            return task.GetResult();
        }

        public void OnCompleted(Action completion)
        {
            task.OnCompleted(completion);
        }
    }
}

public static class CovariantTask
{
    public static ICovariantTask<T> FromResult<T>(T result)
    {
        return new CompletedCovariantTask<T>(result);
    }
}