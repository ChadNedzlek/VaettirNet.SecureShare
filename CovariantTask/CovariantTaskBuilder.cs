using System;
using System.Runtime.CompilerServices;

namespace VaettirNet.Threading.Tasks;

public class CovariantTaskBuilder<T>
{
    private AsyncTaskMethodBuilder<T> _builder = AsyncTaskMethodBuilder<T>.Create();

    public static CovariantTaskBuilder<T> Create() => new CovariantTaskBuilder<T>();

    public void Start<TStateMachine>(ref TStateMachine stateMachine)
        where TStateMachine : IAsyncStateMachine
        => _builder.Start(ref stateMachine);

    public void SetStateMachine(IAsyncStateMachine stateMachine) => _builder.SetStateMachine(stateMachine);
    public void SetException(Exception exception) => _builder.SetException(exception);
    public void SetResult(T result) => _builder.SetResult(result);

    public void AwaitOnCompleted<TAwaiter, TStateMachine>(
        ref TAwaiter awaiter,
        ref TStateMachine stateMachine
    )
        where TAwaiter : INotifyCompletion
        where TStateMachine : IAsyncStateMachine => _builder.AwaitOnCompleted(ref awaiter, ref stateMachine);
    
    public void AwaitUnsafeOnCompleted<TAwaiter, TStateMachine>(
        ref TAwaiter awaiter, ref TStateMachine stateMachine)
        where TAwaiter : ICriticalNotifyCompletion
        where TStateMachine : IAsyncStateMachine => _builder.AwaitUnsafeOnCompleted(ref awaiter, ref stateMachine);

    public ICovariantTask<T> Task => new CovariantTask<T>(_builder.Task);
}