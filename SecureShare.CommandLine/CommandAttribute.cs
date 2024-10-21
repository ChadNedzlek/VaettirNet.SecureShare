using System;
using System.Collections.Generic;

namespace VaettirNet.SecureShare.CommandLine;

[AttributeUsage(AttributeTargets.Class)]
public class CommandAttribute : Attribute
{
    public CommandAttribute(string names)
    {
        Name = names.Split('|');
    }

    public IReadOnlyList<string> Name { get; }
}