using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace VaettirNet.SecureShare.Vaults;

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
        // We don't want to ues "Helpers.GrowingSpan"
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