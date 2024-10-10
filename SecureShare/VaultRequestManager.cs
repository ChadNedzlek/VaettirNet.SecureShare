using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace SecureShare;

public class VaultRequestManager
{
    private readonly MessageEncryptionAlgorithm _encryptionAlgorithm;

    public VaultRequestManager(MessageEncryptionAlgorithm encryptionAlgorithm)
    {
        _encryptionAlgorithm = encryptionAlgorithm;
    }

    public bool TryCreateRequest(
        string description,
        Span<byte> privateKey,
        out int cb,
        [MaybeNullWhen(false)] out VaultRequest client
    )
    {
        return TryCreateRequest(privateKey, description, default, out cb, out client);
    }

    public bool TryCreateRequest(
        Span<byte> privateKey,
        string description,
        ReadOnlySpan<char> password,
        out int cb,
        [MaybeNullWhen(false)] out VaultRequest vault
    )
    {
        Guid clientId = Guid.NewGuid();
        Span<byte> publicKey = stackalloc byte[300];
        byte[]? rented = null;
        if (!_encryptionAlgorithm.TryCreate(password, privateKey, out cb, publicKey, out int cbPublic))
        {
            publicKey = rented = VaultArrayPool.Pool.Rent(2000);
            if (!_encryptionAlgorithm.TryCreate(password, privateKey, out cb, publicKey, out cbPublic))
            {
                VaultArrayPool.Pool.Return(rented);
                vault = null;
                return false;
            }
        }

        vault = new VaultRequest(clientId, description, [..publicKey[..cbPublic]]);

        if (rented != null) VaultArrayPool.Pool.Return(rented);
        return true;
    }
}

public delegate TOut SpanFunc<TIn, TOut>(Span<TIn> span, out int cb);
public delegate TOut SpanFunc<TIn1, TIn2, TOut>(Span<TIn1> a, out int cbA, Span<TIn2> b, out int cbB);

public readonly ref struct RentedSpan<T>
{
    public RentedSpan(Span<T> span)
    {
        Span = span;
    }

    public RentedSpan(Span<T> span, T[] toReturn, ArrayPool<T> pool)
    {
        Span = span;
        _toReturn = toReturn;
        _pool = pool;
    }

    public readonly Span<T> Span;
    private readonly T[]? _toReturn;
    private readonly ArrayPool<T>? _pool;

    public void Dispose()
    {
        if (_toReturn != null) _pool?.Return(_toReturn);
    }
}