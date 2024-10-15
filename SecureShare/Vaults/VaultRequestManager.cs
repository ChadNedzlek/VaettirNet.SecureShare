using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace VaettirNet.SecureShare.Vaults;

public class VaultRequestManager
{
    private readonly VaultCryptographyAlgorithm _encryptionAlgorithm;

    public VaultRequestManager(VaultCryptographyAlgorithm encryptionAlgorithm)
    {
        _encryptionAlgorithm = encryptionAlgorithm;
    }

    public VaultRequest CreateRequest(string description, out PrivateClientInfo privateInfo)
    {
        return CreateRequest(description, default, out privateInfo);
    }

    public VaultRequest CreateRequest(string description, ReadOnlySpan<char> password, out PrivateClientInfo privateInfo)
    {
        ECDsa dsa = ECDsa.Create();
        Guid clientId = Guid.NewGuid();
        _encryptionAlgorithm.Create(password, out privateInfo, out var publicInfo);
        return new VaultRequest(clientId, description, publicInfo.EncryptionKey, publicInfo.SigningKey);
    }
}

public struct PrivateClientInfo
{
    public readonly ReadOnlyMemory<byte> EncryptionKey;
    public readonly ReadOnlyMemory<byte> SigningKey;

    public PrivateClientInfo(ReadOnlyMemory<byte> encryptionKey, ReadOnlyMemory<byte> signingKey)
    {
        EncryptionKey = encryptionKey;
        SigningKey = signingKey;
    }
}
public struct PublicClientInfo
{
    public readonly ReadOnlyMemory<byte> EncryptionKey;
    public readonly ReadOnlyMemory<byte> SigningKey;

    public PublicClientInfo(ReadOnlyMemory<byte> encryptionKey, ReadOnlyMemory<byte> signingKey)
    {
        EncryptionKey = encryptionKey;
        SigningKey = signingKey;
    }
}