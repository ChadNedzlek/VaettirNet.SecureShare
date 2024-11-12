using System;
using VaettirNet.SecureShare.Sync;

namespace VaettirNet.SecureShare;

public readonly struct Validated<T>
    where T : ISignable
{
    private readonly Signed<T> _value;
    public T Value => _value.DangerousGetPayload();
    public Guid Signer => _value.Signer;
    public ReadOnlyMemory<byte> Signature => _value.Signature;
    public bool IsEmpty => _value == null;
    public Signed<T> Signed => _value;

    private Validated(Signed<T> value)
    {
        _value = value;
    }

    public static Validated<T> Validate(Signed<T> signed, ReadOnlySpan<byte> publicKey, VaultCryptographyAlgorithm algorithm)
    {
        if (algorithm.TryValidate(signed, publicKey, out _))
        {
            return new Validated<T>(signed);
        }

        throw new InvalidVaultException("Signed payload is not signed validly");
    }

    public static bool TryValidate(Signed<T> signed, ReadOnlySpan<byte> publicKey, VaultCryptographyAlgorithm algorithm, out Validated<T> validated)
    {
        if (algorithm.TryValidate(signed, publicKey, out _))
        {
            validated = new Validated<T>(signed);
            return true;
        }

        validated = default;
        return false;
    }

    internal static Validated<T> AssertValid(Signed<T> signed) => new(signed);
    
    public static implicit operator T(Validated<T> validated) => validated.Value;
    public static implicit operator Signed<T>(Validated<T> validated) => validated._value;
}

public static class Validated
{
    public static Validated<T> Validate<T>(Signed<T> signed, ReadOnlySpan<byte> publicKey, VaultCryptographyAlgorithm algorithm)
        where T : ISignable => Validated<T>.Validate(signed, publicKey, algorithm);

    public static bool TryValidate<T>(Signed<T> signed, ReadOnlySpan<byte> publicKey, VaultCryptographyAlgorithm algorithm, out Validated<T> validated)
        where T : ISignable => Validated<T>.TryValidate(signed, publicKey, algorithm, out validated);
    
    internal static Validated<T> AssertValid<T>(Signed<T> signed)
        where T : ISignable => Validated<T>.AssertValid(signed);
}