using System;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace SecureShare;

public class VaultManager
{
    private readonly MessageEncryptionAlgorithm _messageEncryptionAlgorithm;
    private readonly SecretTransformer _transformer;

    public VaultManager(SecretTransformer transformer, MessageEncryptionAlgorithm messageEncryptionAlgorithm, SealedVault vault)
    {
        _transformer = transformer;
        _messageEncryptionAlgorithm = messageEncryptionAlgorithm;
        Vault = vault;
    }

    public SealedVault Vault { get; }

    public void AddAuthenticatedClient(ReadOnlySpan<byte> userPrivateKey, VaultRequest request)
    {
        AddAuthenticatedClient(userPrivateKey, default, request);
    }

    public void AddAuthenticatedClient(
        ReadOnlySpan<byte> userPrivateKey,
        ReadOnlySpan<char> password,
        VaultRequest request
    )
    {
        Span<byte> sharedKey = stackalloc byte[_transformer.KeySize];
        _transformer.ExportKey(sharedKey, out _);
        Span<byte> encryptedClientKey = stackalloc byte[100];
        byte[]? rented = null;
        if (!_messageEncryptionAlgorithm.TryEncryptFor(sharedKey,
            userPrivateKey,
            password,
            request.PublicKey.AsSpan(),
            encryptedClientKey,
            out int cb))
        {
            encryptedClientKey = rented = VaultArrayPool.Pool.Rent(2000);
            if (!_messageEncryptionAlgorithm.TryEncryptFor(sharedKey,
                userPrivateKey,
                password,
                request.PublicKey.AsSpan(),
                encryptedClientKey,
                out cb))
            {
                VaultArrayPool.Pool.Return(rented);
                throw new CryptographicException("Unable to allocate enough space");
            }
        }

        if (rented != null) VaultArrayPool.Pool.Return(rented);

        Vault.Data.AddClient(new VaultClientEntry(request.ClientId,
            request.Description,
            request.PublicKey,
            encryptedClientKey[..cb].ToImmutableArray(),
            Vault.ClientId));
    }

    public UnsealedVault Unseal()
    {
        return new UnsealedVault(Vault.Data, _transformer);
    }

    public static VaultManager Import(
        MessageEncryptionAlgorithm messageAlg,
        SealedVault vault,
        ReadOnlySpan<byte> userPrivateKey,
        ReadOnlySpan<char> password = default
    )
    {
        if (!vault.Data.TryGetClient(vault.ClientId, out VaultClientEntry? clientEntry))
            throw new ArgumentException("Client ID is not present in vault data");

        if (!vault.Data.TryGetClient(clientEntry.AuthorizedByClientId, out VaultClientEntry? authorizer))
            throw new ArgumentException("Authorizer is not present");

        Span<byte> sharedKey = stackalloc byte[100];
        byte[]? rented = null;
        if (!messageAlg.TryDecryptFrom(clientEntry.EncryptedSharedKey.AsSpan(),
            userPrivateKey,
            password,
            authorizer.PublicKey.AsSpan(),
            sharedKey,
            out int cb))
        {
            sharedKey = rented = VaultArrayPool.Pool.Rent(2000);
            if (!messageAlg.TryDecryptFrom(clientEntry.EncryptedSharedKey.AsSpan(),
                userPrivateKey,
                password,
                authorizer.PublicKey.AsSpan(),
                sharedKey,
                out cb))
            {
                VaultArrayPool.Pool.Return(rented);
                throw new InvalidOperationException("Unable to read key");
            }
        }

        return new VaultManager(SecretTransformer.CreateFromSharedKey(sharedKey[..cb]), messageAlg, vault);
    }

    public static bool TryInitialize(
        string clientDescription,
        Span<byte> privateKey,
        out int cb,
        [NotNullWhen(true)] out VaultManager? manager
    )
    {
        return TryInitialize(clientDescription, privateKey, default, out cb, out manager);
    }

    public static bool TryInitialize(
        string clientDescription,
        Span<byte> privateKey,
        ReadOnlySpan<char> password,
        out int cb,
        [NotNullWhen(true)] out VaultManager? manager
    )
    {
        MessageEncryptionAlgorithm encryptionAlgorithm = new();
        Guid clientId = Guid.NewGuid();
        Span<byte> publicKey = stackalloc byte[300];
        byte[]? rented = null;
        if (!encryptionAlgorithm.TryCreate(password, privateKey, out cb, publicKey, out int cbPublic))
        {
            publicKey = rented = VaultArrayPool.Pool.Rent(2000);
            if (!encryptionAlgorithm.TryCreate(password, privateKey, out cb, publicKey, out cbPublic))
            {
                VaultArrayPool.Pool.Return(rented);
                manager = null;
                return false;
            }
        }

        manager = new VaultManager(
            SecretTransformer.CreateRandom(),
            encryptionAlgorithm,
            new SealedVault(new VaultData([], []), clientId)
        );
        manager.AddAuthenticatedClient(privateKey, new VaultRequest(clientId, clientDescription, publicKey[..cbPublic].ToImmutableArray()));
        if (rented != null) VaultArrayPool.Pool.Return(rented);
        return true;
    }
}