namespace VaettirNet.SecureShare;

public readonly record struct Signer(VaultCryptographyAlgorithm Algorithm, PrivateClientInfo Keys)
{
    public static implicit operator RefSigner(Signer s) => new RefSigner(s.Algorithm, s.Keys);
}

public readonly ref struct RefSigner
{
    public readonly VaultCryptographyAlgorithm Algorithm;
    public readonly PrivateClientInfo Keys;

    public RefSigner(VaultCryptographyAlgorithm algorithm, PrivateClientInfo keys)
    {
        Algorithm = algorithm;
        Keys = keys;
    }
}