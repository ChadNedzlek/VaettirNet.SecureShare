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