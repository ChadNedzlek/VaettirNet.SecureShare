using System;
using System.Collections.Immutable;
using System.Linq;
using VaettirNet.SecureShare.Secrets;

namespace VaettirNet.SecureShare.Vaults;

public class VaultManager
{
    private readonly VaultCryptographyAlgorithm _vaultCryptographyAlgorithm;
    private readonly SecretTransformer _transformer;

    public VaultManager(SecretTransformer transformer, VaultCryptographyAlgorithm vaultCryptographyAlgorithm, LiveVaultData vault)
    {
        _transformer = transformer;
        _vaultCryptographyAlgorithm = vaultCryptographyAlgorithm;
        Vault = vault;
    }

    public LiveVaultData Vault { get; }

    public VaultClientEntry ApproveRequest(RefSigner signer, VaultRequest request)
    {
        Span<byte> sharedKey = stackalloc byte[_transformer.KeySize];
        var publicInfo = request.PublicInfo;
        _transformer.ExportKey(sharedKey, out _);
        using RentedSpan<byte> encryptedClientKey = SpanHelpers.GrowingSpan(
            stackalloc byte[100],
            RefTuple.Create(signer, (ReadOnlySpan<byte>)sharedKey),
            (Span<byte> span, RefTuple<RefSigner, ReadOnlySpan<byte>> state, out int cb) =>
                _vaultCryptographyAlgorithm.TryEncryptFor(state.Item2, state.Item1.Keys, state.Item1.Password, publicInfo, span, out cb),
            VaultArrayPool.Pool
        );

        return new VaultClientEntry(
            request.ClientId,
            request.Description,
            request.EncryptionKey,
            request.SigningKey,
            encryptedClientKey.Span.ToArray(),
            signer.Keys.ClientId
        );
    }

    public void AddAuthenticatedClient(Signer signer, VaultRequest request)
    {
        Vault.AddClient(ApproveRequest(signer, request), signer);
    }

    private Signed<ClientModificationRecord> SignRecord(
        PrivateClientInfo privateInfo,
        ReadOnlySpan<char> password,
        ClientModificationRecord clientModificationRecord) =>
        _vaultCryptographyAlgorithm.Sign(clientModificationRecord, privateInfo, password);

    public static VaultManager Import(
        VaultCryptographyAlgorithm messageAlg,
        VaultDataSnapshot vault,
        PrivateClientInfo privateInfo,
        ReadOnlySpan<char> password = default
    )
    {
        LiveVaultData live = LiveVaultData.FromSnapshot(vault);
        if (!live.TryGetClient(privateInfo.ClientId, out VaultClientEntry? clientEntry))
            throw new ArgumentException("Client ID is not present in vault data");

        if (!live.TryGetClient(clientEntry.Authorizer, out VaultClientEntry? authorizer))
            throw new ArgumentException("Authorizer is not present");

        using var sharedKey = SpanHelpers.GrowingSpan(
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

        return new VaultManager(SecretTransformer.CreateFromSharedKey(sharedKey.Span), messageAlg, live);
    }

    public static VaultManager Initialize(
        string clientDescription,
        VaultCryptographyAlgorithm vaultCryptographyAlgorithm,
        out PrivateClientInfo privateInfo
    )
    {
        return Initialize(clientDescription, default, vaultCryptographyAlgorithm, out privateInfo);
    }

    public static VaultManager Initialize(
        string clientDescription,
        ReadOnlySpan<char> password,
        VaultCryptographyAlgorithm encryptionAlgorithm,
        out PrivateClientInfo privateInfo
    )
    {
        var requestManager = new VaultRequestManager(encryptionAlgorithm);
        var request = requestManager.CreateRequest(clientDescription, out privateInfo);

        SecretTransformer transformer = SecretTransformer.CreateRandom();
        var manager = new VaultManager(
            transformer,
            encryptionAlgorithm,
            new LiveVaultData()
        );
        RefSigner signer = new(encryptionAlgorithm, privateInfo, password);
        VaultClientEntry clientEntry = manager.ApproveRequest(signer, request);
        manager.Vault.AddClient(clientEntry, signer);
        return manager;
    }

    public SecretTransformer GetTransformer(PrivateClientInfo clientInfo)
    {
        VaultClientEntry vaultClient = Vault.Clients.First(v => v.ClientId == clientInfo.ClientId);
        VaultClientEntry authorizer = Vault.Clients.First(v => v.ClientId == vaultClient.Authorizer);
        ReadOnlySpan<byte> encryptedKey = vaultClient.EncryptedSharedKey.Span;
        Span<byte> decryptedKey = stackalloc byte[SecretTransformer.KeySizeInBytes];
        if (!_vaultCryptographyAlgorithm.TryDecryptFrom(encryptedKey, clientInfo, authorizer.PublicInfo, decryptedKey, out int written))
        {
            throw new InvalidOperationException();
        }
        return SecretTransformer.CreateFromSharedKey(decryptedKey);
    }
}