using System;
using System.Collections.Immutable;
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

    public void AddAuthenticatedClient(PrivateClientInfo privateInfo, VaultRequest request)
    {
        AddAuthenticatedClient(privateInfo, default, request);
    }

    public VaultClientEntry ApproveRequest(PrivateClientInfo privateInfo, VaultRequest request)
    {
        return ApproveRequest(privateInfo, default, request);
    }

    public VaultClientEntry ApproveRequest(
        PrivateClientInfo privateInfo,
        ReadOnlySpan<char> password,
        VaultRequest request)
    {
        Span<byte> sharedKey = stackalloc byte[_transformer.KeySize];
        var publicInfo = request.PublicInfo;
        _transformer.ExportKey(sharedKey, out _);
        using RentedSpan<byte> encryptedClientKey = Helpers.GrowingSpan(
            stackalloc byte[100],
            RefTuple.Create((ReadOnlySpan<byte>)sharedKey, password),
            (Span<byte> span, RefTuple<ReadOnlySpan<byte>, ReadOnlySpan<char>> state, out int cb) =>
                _vaultCryptographyAlgorithm.TryEncryptFor(state.Item1, privateInfo, state.Item2, publicInfo, span, out cb),
            VaultArrayPool.Pool);

        return new VaultClientEntry{
            ClientId = request.ClientId,
            Description = request.Description,
            EncryptionKey = request.EncryptionKey,
            SigningKey = request.SigningKey,
            EncryptedSharedKey = encryptedClientKey.Span.ToArray()
        };
    }

    public void AddAuthenticatedClient(
        PrivateClientInfo privateInfo,
        ReadOnlySpan<char> password,
        VaultRequest request
    )
    {
        Vault.Data.AddClient(ApproveRequest(privateInfo, password, request));
        Vault.Data.AddModificationRecord(
            SignRecord(privateInfo, password,
                new ClientModificationRecord
                {
                    Action = ClientAction.Added, EncryptionKey = request.EncryptionKey, SigningKey = request.SigningKey,
                    Authorizer = Vault.ClientId, Client = request.ClientId
                }));
        
    }

    private Signed<ClientModificationRecord> SignRecord(
        PrivateClientInfo privateInfo,
        ReadOnlySpan<char> password,
        ClientModificationRecord clientModificationRecord) =>
        _vaultCryptographyAlgorithm.Sign(clientModificationRecord, privateInfo, password);

    public UnsealedVault Unseal()
    {
        return new UnsealedVault(Vault.Data, _transformer);
    }

    public static VaultManager Import(
        VaultCryptographyAlgorithm messageAlg,
        SealedVault vault,
        PrivateClientInfo privateInfo,
        ReadOnlySpan<char> password = default
    )
    {
        if (!vault.Data.TryGetClient(vault.ClientId, out VaultClientEntry? clientEntry))
            throw new ArgumentException("Client ID is not present in vault data");
        
        ImmutableArray<Signed<ClientModificationRecord>> mods = vault.Data.GetModificationRecords(vault.ClientId);
        if (mods.Length != 1)
        {
            throw new ArgumentException("Could not find addition record");
        }

        if (!vault.Data.TryGetClient(mods[0].Authorizer, out VaultClientEntry? authorizer))
            throw new ArgumentException("Authorizer is not present");

        using var sharedKey = Helpers.GrowingSpan(
            stackalloc byte[300],
            password,
            (Span<byte> s, ReadOnlySpan<char> pw, out int cb) => messageAlg.TryDecryptFrom(
                clientEntry.EncryptedSharedKey.Span,
                privateInfo,
                pw,
                authorizer.PublicInfo,
                s,
                out cb),
            VaultArrayPool.Pool);

        return new VaultManager(SecretTransformer.CreateFromSharedKey(sharedKey.Span), messageAlg, vault);
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
        VaultClientEntry clientEntry = manager.ApproveRequest(privateInfo, password, request);
        manager.Vault.Data.AddClient(clientEntry);
        return manager;
    }
}