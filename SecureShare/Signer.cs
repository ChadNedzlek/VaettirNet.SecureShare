using VaettirNet.SecureShare.Crypto;

namespace VaettirNet.SecureShare;

public readonly record struct Signer(VaultCryptographyAlgorithm Algorithm, PrivateKeyInfo Keys)
{
    public static implicit operator RefSigner(Signer s) => new RefSigner(s.Algorithm, s.Keys);
}

public readonly ref struct RefSigner
{
    public readonly VaultCryptographyAlgorithm Algorithm;
    public readonly PrivateKeyInfo Keys;

    public RefSigner(VaultCryptographyAlgorithm algorithm, PrivateKeyInfo keys)
    {
        Algorithm = algorithm;
        Keys = keys;
    }
}