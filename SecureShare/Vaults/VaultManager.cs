using System;
using System.Diagnostics.CodeAnalysis;
using VaettirNet.SecureShare.Secrets;

namespace VaettirNet.SecureShare.Vaults;

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

    public VaultClientEntry SignRequest(
        ReadOnlySpan<byte> userPrivateKey,
        VaultRequest request)
    {
        return SignRequest(userPrivateKey, default, request);
    }

    public VaultClientEntry SignRequest(
        ReadOnlySpan<byte> userPrivateKey,
        ReadOnlySpan<char> password,
        VaultRequest request)
    {
        Span<byte> sharedKey = stackalloc byte[_transformer.KeySize];
        _transformer.ExportKey(sharedKey, out _);
        using RentedSpan<byte> encryptedClientKey = Helpers.GrowingSpan(
            stackalloc byte[100],
            (Span<byte> span, ReadOnlySpanTuple<byte, byte, char> state, out int cb) =>
                _messageEncryptionAlgorithm.TryEncryptFor(state.Span1, state.Span2, state.Span3, request.PublicKey.Span, span, out cb),
            SpanTuple.Create((ReadOnlySpan<byte>)sharedKey, userPrivateKey, password),
            VaultArrayPool.Pool
        );

        return new VaultClientEntry(request.ClientId,
            request.Description,
            request.PublicKey,
            encryptedClientKey.Span.ToArray(),
            Vault.ClientId);
    }

    public void AddAuthenticatedClient(
        ReadOnlySpan<byte> userPrivateKey,
        ReadOnlySpan<char> password,
        VaultRequest request
    )
    {
        Vault.Data.AddClient(SignRequest(userPrivateKey, password, request));
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
        if (!messageAlg.TryDecryptFrom(clientEntry.EncryptedSharedKey.Span,
            userPrivateKey,
            password,
            authorizer.PublicKey.Span,
            sharedKey,
            out int cb))
        {
            byte[]? rented;
            sharedKey = rented = VaultArrayPool.Pool.Rent(2000);
            if (!messageAlg.TryDecryptFrom(clientEntry.EncryptedSharedKey.Span,
                userPrivateKey,
                password,
                authorizer.PublicKey.Span,
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
        var requestManager = new VaultRequestManager(encryptionAlgorithm);
        if (!requestManager.TryCreateRequest(clientDescription, privateKey, out cb, out var request))
        {
            manager = null;
            return false;
        }

        SecretTransformer transformer = SecretTransformer.CreateRandom();
        manager = new VaultManager(transformer,
            encryptionAlgorithm,
            new SealedVault(new VaultData(),request.ClientId)
            );
        VaultClientEntry clientEntry = manager.SignRequest(privateKey, password, request);
        manager.Vault.Data.AddClient(clientEntry);
        return true;
    }
}