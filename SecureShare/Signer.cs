using System;

namespace VaettirNet.SecureShare.Vaults;

public readonly record struct Signer(VaultCryptographyAlgorithm Algorithm, PrivateClientInfo Keys, ReadOnlyMemory<char> Password = default)
{
    public static implicit operator RefSigner(Signer s) => new RefSigner(s.Algorithm, s.Keys, s.Password.Span);
}

public readonly ref struct RefSigner
{
    public readonly VaultCryptographyAlgorithm Algorithm;
    public readonly PrivateClientInfo Keys;
    public readonly ReadOnlySpan<char> Password;

    public RefSigner(VaultCryptographyAlgorithm algorithm, PrivateClientInfo keys, ReadOnlySpan<char> password = default)
    {
        Algorithm = algorithm;
        Keys = keys;
        Password = password;
    }
}