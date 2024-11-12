using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Microsoft.Extensions.DependencyInjection;

namespace VaettirNet.SecureShare.CommandLine;

public interface ICommandSet<TState>
{
    ICommand<TState> RootCommand { get; }
    ICommand<TState, TParent> GetChildCommand<TParent>(string name)
        where TParent : ICommand<TState>;

    ICommand<TState> GetChildCommand(Type parent, string name);
}

public class CommandSet<TState> 
{
    private Dictionary<(Type parent, string name), Type> _commands;

    private CommandSet(Dictionary<(Type parent, string name), Type> commands)
    {
        _commands = commands;
    }

    private class ScopedSet : ICommandSet<TState>
    {
        private readonly CommandSet<TState> _unscoped;
        private readonly IServiceScope _scope;

        public ScopedSet(CommandSet<TState> unscoped, IServiceScope scope)
        {
            _unscoped = unscoped;
            _scope = scope;
        }

        public ICommand<TState> RootCommand => _unscoped.GetChildCommand(_scope.ServiceProvider, null, null);

        public ICommand<TState, TParent> GetChildCommand<TParent>(string name)
            where TParent : ICommand<TState> => (ICommand<TState, TParent>)_unscoped.GetChildCommand(_scope.ServiceProvider, typeof(TParent), name);

        public ICommand<TState> GetChildCommand(Type parent, string name) => _unscoped.GetChildCommand(_scope.ServiceProvider, parent, name);
    }

    public ICommandSet<TState> GetScoped(IServiceScope scope) => new ScopedSet(this, scope);

    private ICommand<TState> GetChildCommand(IServiceProvider services, Type parent, string name)
    {
        if (_commands.TryGetValue((parent, name.ToLowerInvariant()), out Type childCommand))
        {
            return (ICommand<TState>)ActivatorUtilities.CreateInstance(services, childCommand);
        }

        return null;
    }

    public static CommandSet<TState> CreateFromAssembly(Assembly assembly)
    {
        Dictionary<(Type parent, string name), Type> set = new();
        IEnumerable<Type> commands = assembly.GetTypes().Where(t => !t.IsInterface && !t.IsAbstract && typeof(ICommand<TState>).IsAssignableFrom(t));
        foreach (Type command in commands)
        {
            if (command.GetInterfaces().FirstOrDefault(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(ICommand<,>)) is
                { } childCommandInterface)
            {
                AddCommand(set, command, childCommandInterface.GenericTypeArguments[1]);
            }
            else
            {
                AddCommand(set, command);
            }
        }

        if (!set.ContainsKey((null, null)))
        {
            set.Add((null, null), typeof(RootCommand<TState>));
        }

        return new CommandSet<TState>(set);

        static void AddCommand(Dictionary<(Type parent, string name), Type> set, Type command, Type parent = null)
        {
            IReadOnlyList<string> names = NormalizedCommandName(command);
            foreach (string name in names)
            {
                set.Add((parent, name.ToLowerInvariant()), command);
            }
        }

        static IReadOnlyList<string> NormalizedCommandName(Type type)
        {
            if (type.GetCustomAttribute<CommandAttribute>() is { } commandAttribute)
            {
                return commandAttribute.Name;
            }

            if (type.Name.EndsWith("Command"))
            {
                return [type.Name[..^7]];
            }

            return [type.Name];
        }
    }
}