using System.Collections.Immutable;
using System.Threading.Tasks;
using JetBrains.Annotations;

namespace VaettirNet.SecureShare.CommandLine;

[UsedImplicitly(ImplicitUseKindFlags.InstantiatedNoFixedConstructorSignature,ImplicitUseTargetFlags.WithInheritors)]
public interface ICommand<TState>
{
    Task<int> ExecuteAsync(ICommandSet<TState> commandSet, TState state, ICommand<TState> parent, ImmutableList<string> args);
}