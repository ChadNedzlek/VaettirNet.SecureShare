using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace VaettirNet.Threading.Tasks;

[AsyncMethodBuilder(typeof(CovariantTaskBuilder<>))]
public interface ICovariantTask<out TResult>
{
    ICovariantAwaiter<TResult> GetAwaiter();
    Task AsTaskBase();
}