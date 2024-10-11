using System.Threading.Tasks;

namespace VaettirNet.Threading.Tasks;

public static class CovariantTaskExtensions
{
    public static Task<T> AsTask<T>(this ICovariantTask<T> covariantTask) => (Task<T>)covariantTask.AsTaskBase();
    public static ICovariantTask<T> AsCovariant<T>(this Task<T> task) => new CovariantTask<T>(task);
}