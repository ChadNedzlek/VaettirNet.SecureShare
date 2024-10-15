using System;
using System.Diagnostics.CodeAnalysis;
using VaettirNet.SecureShare.Secrets;

namespace VaettirNet.SecureShare.Vaults;

public class VaultManager
{
    private readonly VaultCryptographyAlgorithm _vaultCryptographyAlgorithm;
    private readonly SecretTransformer _transformer;

    public VaultManager(SecretTransformer transformer, VaultCryptographyAlgorithm vaultCryptographyAlgorithm, SealedVault vault)
    {
        _transformer = transformer;
        _vaultCryptographyAlgorithm = vaultCryptographyAlgorithm;
        Vault = vault;
    }

    public SealedVault Vault { get; }

    public void AddAuthenticatedClient(ReadOnlySpan<byte> userPrivateKey, VaultRequest request)
    {
        AddAuthenticatedClient(userPrivateKey, default, request);
    }

    public VaultClientEntry ApproveRequest(
        ReadOnlySpan<byte> userPrivateKey,
        VaultRequest request)
    {
        return ApproveRequest(userPrivateKey, default, request);
    }

    public VaultClientEntry ApproveRequest(
        ReadOnlySpan<byte> userPrivateKey,
        ReadOnlySpan<char> password,
        VaultRequest request)
    {
        Span<byte> sharedKey = stackalloc byte[_transformer.KeySize];
        _transformer.ExportKey(sharedKey, out _);
        using RentedSpan<byte> encryptedClientKey = Helpers.GrowingSpan(
            stackalloc byte[100],
            (Span<byte> span, RefTuple<ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<char>> state, out int cb) =>
                _vaultCryptographyAlgorithm.TryEncryptFor(state.Item1, state.Item2, state.Item3, request.EncryptionKey.Span, span, out cb),
            RefTuple.Create((ReadOnlySpan<byte>)sharedKey, userPrivateKey, password),
            VaultArrayPool.Pool
        );

        return new VaultClientEntry(request.ClientId,
            request.Description,
            request.EncryptionKey,
            request.SigningKey,
            encryptedClientKey.Span.ToArray(),
            Vault.ClientId);
    }

    public void AddAuthenticatedClient(
        ReadOnlySpan<byte> userPrivateKey,
        ReadOnlySpan<char> password,
        VaultRequest request
    )
    {
        Vault.Data.AddClient(ApproveRequest(userPrivateKey, password, request));
    }

    public UnsealedVault Unseal()
    {
        return new UnsealedVault(Vault.Data, _transformer);
    }

    public static VaultManager Import(
        VaultCryptographyAlgorithm messageAlg,
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
        if (!messageAlg.TryDecryptFrom(clientEntry.EncryptedSharedKey.Span,
            userPrivateKey,
            password,
            authorizer.EncryptionKey.Span,
            sharedKey,
            out int cb))
        {
            byte[]? rented;
            sharedKey = rented = VaultArrayPool.Pool.Rent(2000);
            if (!messageAlg.TryDecryptFrom(clientEntry.EncryptedSharedKey.Span,
                userPrivateKey,
                password,
                authorizer.EncryptionKey.Span,
                sharedKey,
                out cb))
            {
                VaultArrayPool.Pool.Return(rented);
                throw new InvalidOperationException("Unable to read key");
            }
        }

        return new VaultManager(SecretTransformer.CreateFromSharedKey(sharedKey[..cb]), messageAlg, vault);
    }

    public static VaultManager Initialize(string clientDescription, out PrivateClientInfo privateInfo)
    {
        return Initialize(clientDescription, default, out privateInfo);
    }

    public static VaultManager Initialize(string clientDescription, ReadOnlySpan<char> password, out PrivateClientInfo privateInfo)
    {
        VaultCryptographyAlgorithm encryptionAlgorithm = new();
        var requestManager = new VaultRequestManager(encryptionAlgorithm);
        var request = requestManager.CreateRequest(clientDescription, out privateInfo);

        SecretTransformer transformer = SecretTransformer.CreateRandom();
        var manager = new VaultManager(
            transformer,
            encryptionAlgorithm,
            new SealedVault(new VaultData(), request.ClientId)
        );
        VaultClientEntry clientEntry = manager.ApproveRequest(privateInfo.EncryptionKey.Span, password, request);
        manager.Vault.Data.AddClient(clientEntry);
        return manager;
    }
}