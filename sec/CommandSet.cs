using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace sec;

public class CommandSet<TState>
{
    private Dictionary<(Type parent, string name), Type> _commands;

    private CommandSet(Dictionary<(Type parent, string name), Type> commands)
    {
        _commands = commands;
    }

    public ICommand<TState> RootCommand => (ICommand<TState>)Activator.CreateInstance(_commands[(null, null)]);

    public ICommand<TState, TParent> GetChildCommand<TParent>(string name)
        where TParent : ICommand<TState>
    {
        return (ICommand<TState, TParent>)GetChildCommand(typeof(TParent), name);
    }
    
    public ICommand<TState> GetChildCommand(Type parent, string name)
    {
        if (_commands.TryGetValue((parent, name.ToLowerInvariant()), out Type childCommand))
        {
            return (ICommand<TState>)Activator.CreateInstance(childCommand);
        }

        return null;
    }

    public static CommandSet<TState> CreateFromAssembly(Assembly assembly)
    {
        Dictionary<(Type parent, string name), Type> set = new();
        var commands = assembly.GetTypes().Where(t => !t.IsInterface && !t.IsAbstract && typeof(ICommand<TState>).IsAssignableFrom(t));
        foreach (var command in commands)
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