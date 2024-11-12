using System;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare.Sync;

public class InvalidVaultException : Exception
{
    public UnvalidatedVaultDataSnapshot? UnvalidatedVault { get; }
    public InvalidVaultException()
    {
    }

    public InvalidVaultException(string? message) : base(message)
    {
    }

    public InvalidVaultException(string? message, Exception? innerException) : base(message, innerException)
    {
    }
    
    public InvalidVaultException(UnvalidatedVaultDataSnapshot invalidUnvalidatedVault) : this()
    {
        UnvalidatedVault = invalidUnvalidatedVault;
    }

    public InvalidVaultException(UnvalidatedVaultDataSnapshot invalidUnvalidatedVault, string? message) : this(message)
    {
        UnvalidatedVault = invalidUnvalidatedVault;
    }

    public InvalidVaultException(UnvalidatedVaultDataSnapshot invalidUnvalidatedVault, string? message, Exception? innerException) : this(message, innerException)
    {
        UnvalidatedVault = invalidUnvalidatedVault;
    }
}