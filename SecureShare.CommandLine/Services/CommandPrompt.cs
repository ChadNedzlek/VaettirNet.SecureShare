using System;

namespace VaettirNet.SecureShare.CommandLine.Services;

public class CommandPrompt
{
    private static object _consoleLock = new();

    public void WriteLine(string value)
    {
        lock (_consoleLock)
        {
            Console.WriteLine(value);
        }
    }
    
    public void WriteLine(string value, ConsoleColor foreground)
    {
        lock (_consoleLock)
        {
            Console.ForegroundColor = foreground;
            Console.WriteLine(value);
            Console.ResetColor();
        }
    }

    public void Write(string value)
    {
        lock (_consoleLock)
        {
            Console.Write(value);
        }
    }
    
    public void Write(ConsoleColor foreground, string value)
    {
        lock (_consoleLock)
        {
            Console.ForegroundColor = foreground;
            Console.Write(value);
            Console.ResetColor();
        }
    }
    
    public void WriteError(string value)
    {
        lock (_consoleLock)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Error.WriteLine(value);
            Console.ResetColor();
        }
    }
    
    public void WriteWarning(string value)
    {
        lock (_consoleLock)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Error.WriteLine(value);
            Console.ResetColor();
        }
    }

    public string Prompt(string prompt)
    {
        lock (_consoleLock)
        {
            Console.Write(prompt);
            return Console.ReadLine();
        }
    }

    public bool Confirm(string prompt)
    {
        lock (_consoleLock)
        {
            while (true)
            {
                Console.Write(prompt);
                switch (Console.ReadLine()?.ToLowerInvariant())
                {
                    case "yes":
                    case "y":
                        return true;
                    case "no":
                    case "n":
                        return false;
                }
            }
        }
    }
}