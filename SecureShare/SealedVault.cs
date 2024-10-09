using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace SecureShare;

public class VaultData
{
    private readonly List<VaultClientEntry> _clients;
    private readonly Dictionary<string, List<string>> _typedStores;

    public VaultData(List<VaultClientEntry> clients, Dictionary<string, List<string>> typedStores)
    {
        _clients = clients;
        _typedStores = typedStores;
    }

    public IEnumerable<VaultClientEntry> Clients => _clients.AsReadOnly();

    public void AddClient(Guid id, ReadOnlySpan<byte> publicKey)
    {
        _clients.Add(new VaultClientEntry(id, publicKey.ToArray()));
    }

    public void AddClient(VaultClientEntry client) => AddClient(client.ClientId, client.PublicKey);

    public void AddStore<TAttribute, TProtected>(SecretStore<TAttribute, TProtected> store)
    {
        string key = typeof(TAttribute).FullName + '|' + typeof(TProtected).FullName;
        SecretSerializer serializer = new();
        _typedStores[key] = store.Select(serializer.Serialize).ToList();
    }

    public SecretStore<TAttribute, TProtected> GetStore<TAttribute, TProtected>(SecretTransformer transformer)
    {
        string key = typeof(TAttribute).FullName + '|' + typeof(TProtected).FullName;
        var store = new SecretStore<TAttribute, TProtected>(transformer);
        if (_typedStores.TryGetValue(key, out List<string>? list))
        {
            SecretSerializer serializer = new();
            foreach (string line in list)
            {
                store.Set(serializer.Deserialize<TAttribute, TProtected>(line));
            }
        }

        return store;
    }

    public static async Task<VaultData> Deserialize(Stream stream)
    {
        using StreamReader reader = new StreamReader(stream, leaveOpen: true);
        string? clientLine = await reader.ReadLineAsync();
        if (clientLine == null)
        {
            throw new ArgumentException("Invalid vault format", nameof(stream));
        }

        List<VaultClientEntry> clients = JsonSerializer.Deserialize<List<VaultClientEntry>>(clientLine) ??
            throw new ArgumentException("Invalid vault format", nameof(stream));

        string? currentType = null;
        List<string> entries = [];
        Dictionary<string, List<string>> typedVaults = [];
        while (await reader.ReadLineAsync() is string line)
        {
            if (line.StartsWith('{'))
            {
                entries.Add(line);
            }
            else
            {
                if (currentType != null)
                {
                    typedVaults.Add(currentType, entries);
                    entries = [];
                }
                else
                {
                    throw new ArgumentException("Invalid vault format", nameof(stream));
                }
            }
        }

        if (currentType != null)
        {
            typedVaults.Add(currentType, entries);
        }

        return new VaultData(clients, typedVaults);
    }

    public async Task Serialize(Stream stream)
    {
        await using StreamWriter writer = new(stream, leaveOpen: true);
        await writer.WriteLineAsync(JsonSerializer.Serialize(_clients));
        foreach (var (type, data) in _typedStores)
        {
            await writer.WriteLineAsync(type);
            foreach (var line in data)
            {
                await writer.WriteLineAsync(line);
            }
        }
    }

    public bool HasPublicKey(Guid clientId)
    {
        return _clients.Any(c => c.ClientId == clientId);
    }

    public byte[] GetPublicKey(Guid clientId)
    {
        return _clients.FirstOrDefault(c => c.ClientId == clientId)?.PublicKey ?? throw new KeyNotFoundException();
    }
}

public record VaultClientEntry(Guid ClientId, byte[] PublicKey);

public class VaultManager
{
    private readonly SecretTransformer _transformer;
    private readonly VaultData _vault;
    private readonly Guid _clientId;

    public VaultManager(SecretTransformer transformer, VaultData vault, Guid clientId)
    {
        _transformer = transformer;
        _vault = vault;
        _clientId = clientId;
    }

    public SealedVault AsSealed()
    {
        return new SealedVault(_vault, _clientId);
    }

    public bool TryGetShareKey(
        Guid targetClientId,
        ReadOnlySpan<byte> userPrivateKey,
        Span<byte> message,
        out int cb
    )
    {
        return TryGetShareKey(targetClientId, userPrivateKey, default, message, out cb);
    }

    public bool TryGetShareKey(
        Guid targetClientId,
        ReadOnlySpan<byte> userPrivateKey,
        ReadOnlySpan<char> password,
        Span<byte> message,
        out int cb
    )
    {
        int cbTag = AesGcm.TagByteSizes.MaxSize;
        int cbNonce = AesGcm.NonceByteSizes.MaxSize;
        int targetSize = sizeof(long) + (256 / 8);
        cb = cbNonce + cbTag + targetSize;
        if (message.Length < cb)
        {
            return false;
        }

        Span<byte> nonce = message[..cbNonce];
        Span<byte> tag = message.Slice(cbNonce, cbTag);
        Span<byte> cipherText = message.Slice(cbNonce + cbTag);
        Span<byte> plainText = stackalloc byte[targetSize];
        ref long ticks = ref MemoryMarshal.AsRef<long>(plainText.Slice(0, sizeof(long)));
        Span<byte> sharedKey = plainText.Slice(sizeof(long));
        
        RandomNumberGenerator.Fill(nonce);
        ticks = DateTimeOffset.UtcNow.Ticks;
        _transformer.ExportKey(sharedKey);
        
        ECDiffieHellman dh = ECDiffieHellman.Create();
        if (password.IsEmpty)
            dh.ImportPkcs8PrivateKey(userPrivateKey, out _);
        else
            dh.ImportEncryptedPkcs8PrivateKey(password, userPrivateKey, out _);
        
        using var pub = ECDiffieHellman.Create();
        pub.ImportSubjectPublicKeyInfo(_vault.GetPublicKey(targetClientId), out _);
        
        byte[] key = dh.DeriveKeyMaterial(pub.PublicKey);
        
        using AesGcm aes = new(key, cbTag);
        aes.Encrypt(
            nonce,
            plainText,
            cipherText,
            tag
        );
        return true;
    }

    public UnsealedVault Unseal()
    {
        return new UnsealedVault(_vault, _transformer);
    }

    public static VaultManager Import(SealedVault vault, ReadOnlySpan<byte> userPrivateKey, ReadOnlySpan<byte> message, ReadOnlySpan<char> password = default)
    {
        if (!vault.Data.HasPublicKey(vault.ClientId))
        {
            throw new ArgumentException("Client ID is not present in vault data");
        }

        int cbTag = AesGcm.TagByteSizes.MaxSize;
        int cbNonce = AesGcm.NonceByteSizes.MaxSize;
        int cbText = message.Length - cbNonce - cbTag;
        int targetSize = sizeof(long) + (256 / 8);
        if (cbText != targetSize)
            throw new ArgumentException("key material incorrect length", nameof(message));
        
        ECDiffieHellman dh = ECDiffieHellman.Create();
        if (password.IsEmpty)
            dh.ImportPkcs8PrivateKey(userPrivateKey, out _);
        else
            dh.ImportEncryptedPkcs8PrivateKey(password, userPrivateKey, out _);
        Span<byte> text = stackalloc byte[targetSize];
        foreach (VaultClientEntry client in vault.Data.Clients)
        {
            try
            {
                using var pub = ECDiffieHellman.Create();
                pub.ImportSubjectPublicKeyInfo(client.PublicKey, out _);
                byte[] key = dh.DeriveKeyMaterial(pub.PublicKey);
                using AesGcm aes = new(key, cbTag);
                aes.Decrypt(
                    message.Slice(0, cbNonce),
                    message.Slice(cbNonce + cbTag),
                    message.Slice(cbNonce, cbTag),
                    text
                );
                var ticks = MemoryMarshal.Read<long>(text);
                var dt = new DateTimeOffset(ticks, TimeSpan.Zero);
                if (dt.AddSeconds(30) < DateTimeOffset.UtcNow)
                {
                    // This thing is too old, not what I'm looking for
                    continue;
                }

                return new VaultManager(SecretTransformer.CreateFromSharedKey(text[sizeof(long)..]), vault.Data, vault.ClientId);
            }
            catch (CryptographicException ex)
            {
                continue;
            }
        }

        throw new Exception("Key not from valid client!!!");
    }

    public static bool TryInitialize(
        Span<byte> privateKey,
        out int cb,
        [NotNullWhen(true)] out VaultManager? manager
    )
    {
        return TryInitialize(privateKey, default, out cb, out manager);
    }

    public static bool TryInitialize(
        Span<byte> privateKey,
        ReadOnlySpan<char> password,
        out int cb,
        [NotNullWhen(true)] out VaultManager? manager
    )
    {
        using var ecc = ECDiffieHellman.Create();
        if (password.IsEmpty)
        {
            if (!ecc.TryExportPkcs8PrivateKey(privateKey, out cb))
            {
                manager = null;
                return false;
            }
        }
        else
        {
            if (!ecc.TryExportEncryptedPkcs8PrivateKey(password,
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA512, 10000),
                privateKey,
                out cb))
            {
                manager = null;
                return false;
            }
        }

        Guid clientId = Guid.NewGuid();
        byte[] publicKey = ecc.PublicKey.ExportSubjectPublicKeyInfo();
        manager = new VaultManager(
            SecretTransformer.CreateRandom(),
            new VaultData([new VaultClientEntry(clientId, publicKey)], []),
            clientId
        );
        return true;
    }

    public static bool TryPrepareForImport(
        VaultData data,
        Span<byte> privateKey,
        out int cb,
        [NotNullWhen(true)] out SealedVault? client
    )
    {
        return TryPrepareForImport(data, privateKey, default, out cb, out client);
    }

    public static bool TryPrepareForImport(
        VaultData data,
        Span<byte> privateKey,
        ReadOnlySpan<char> password,
        out int cb,
        [NotNullWhen(true)]
        out SealedVault? vault
    )
    {
        using var ecc = ECDiffieHellman.Create();
        if (password.IsEmpty)
        {
            if (!ecc.TryExportPkcs8PrivateKey(privateKey, out cb))
            {
                vault = null;
                return false;
            }
        }
        else
        {
            if (!ecc.TryExportEncryptedPkcs8PrivateKey(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA512, 10000), privateKey, out cb))
            {
                vault = null;
                return false;
            }
        }

        Guid clientId = Guid.NewGuid();
        byte[] publicKey = ecc.PublicKey.ExportSubjectPublicKeyInfo();
        data.AddClient(clientId, publicKey);
        vault = new SealedVault(data, clientId);
        return true;
    }
}

public class SealedVault
{
    public VaultData Data { get; }
    public Guid ClientId { get; }

    public SealedVault(VaultData data, Guid clientId)
    {
        Data = data;
        ClientId = clientId;
    }
}

public class UnsealedVault
{
    public VaultData Vault { get; }
    private readonly SecretTransformer _transformer;

    internal UnsealedVault(VaultData vault, SecretTransformer transformer)
    {
        _transformer = transformer;
        Vault = vault;
    }

    public SecretStore<TAttributes, TProtected> CreateStore<TAttributes, TProtected>() =>
        new SecretStore<TAttributes, TProtected>(_transformer);
}