using System;
using System.Security.Cryptography;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare;

public class VaultCryptographyAlgorithm
{
    public bool TryEncryptFor(
        ReadOnlySpan<byte> plainText,
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> otherPublicKey,
        Span<byte> encrypted,
        out int bytesWritten
    )
    {
        return TryEncryptFor(plainText, privateKey, default, otherPublicKey, encrypted, out bytesWritten);
    }

    public bool TryEncryptFor(
        ReadOnlySpan<byte> plainText,
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<char> password,
        ReadOnlySpan<byte> otherPublicKey,
        Span<byte> encrypted,
        out int bytesWritten
    )
    {
        using Aes aes = Aes.Create();
        bytesWritten = plainText.Length + 2 * (aes.BlockSize / 8) - plainText.Length % (aes.BlockSize / 8);
        if (bytesWritten > encrypted.Length) return false;

        using ECDiffieHellman self = ECDiffieHellman.Create();
        if (password.IsEmpty)
            self.ImportPkcs8PrivateKey(privateKey, out _);
        else
            self.ImportEncryptedPkcs8PrivateKey(password, privateKey, out _);

        using ECDiffieHellman other = ECDiffieHellman.Create();
        other.ImportSubjectPublicKeyInfo(otherPublicKey, out _);
        using ECDiffieHellmanPublicKey otherPublicKeyHandle = other.PublicKey;
        byte[] key = self.DeriveKeyMaterial(otherPublicKeyHandle);

        aes.Key = key;
        Span<byte> iv = encrypted.Slice(0, aes.BlockSize / 8);
        Span<byte> cipherText = encrypted.Slice(iv.Length);
        RandomNumberGenerator.Fill(iv);
        return aes.TryEncryptCbc(plainText, iv, cipherText, out _);
    }

    public bool TryDecryptFrom(
        ReadOnlySpan<byte> encrypted,
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> otherPublicKey,
        Span<byte> plainText,
        out int bytesWritten
    )
    {
        return TryDecryptFrom(encrypted, privateKey, default, otherPublicKey, plainText, out bytesWritten);
    }

    public bool TryDecryptFrom(
        ReadOnlySpan<byte> encrypted,
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<char> password,
        ReadOnlySpan<byte> otherPublicKey,
        Span<byte> plainText,
        out int bytesWritten
    )
    {
        using Aes aes = Aes.Create();

        using ECDiffieHellman self = ECDiffieHellman.Create();
        if (password.IsEmpty)
            self.ImportPkcs8PrivateKey(privateKey, out _);
        else
            self.ImportEncryptedPkcs8PrivateKey(password, privateKey, out _);

        using ECDiffieHellman other = ECDiffieHellman.Create();
        other.ImportSubjectPublicKeyInfo(otherPublicKey, out _);
        using ECDiffieHellmanPublicKey otherPublicKeyHandle = other.PublicKey;
        byte[] key = self.DeriveKeyMaterial(otherPublicKeyHandle);

        aes.Key = key;
        ReadOnlySpan<byte> iv = encrypted.Slice(0, aes.BlockSize / 8);
        ReadOnlySpan<byte> cipherText = encrypted.Slice(iv.Length);
        return aes.TryDecryptCbc(cipherText, iv, plainText, out bytesWritten);
    }

    public void Create(out PrivateClientInfo privateInfo, out PublicClientInfo publicInfo) => Create(default, out privateInfo, out publicInfo);

    public void Create(ReadOnlySpan<char> password, out PrivateClientInfo privateInfo, out PublicClientInfo publicInfo)
    {
        using ECDiffieHellman enc = ECDiffieHellman.Create();
        byte[] encryptionPrivateKeyBytes = new byte[200];
        int cbEncryptionPrivateKey;
        if (password.IsEmpty)
        {
            while (!enc.TryExportPkcs8PrivateKey(encryptionPrivateKeyBytes, out cbEncryptionPrivateKey))
            {
                encryptionPrivateKeyBytes = new byte[encryptionPrivateKeyBytes.Length + 100];
            }
        }
        else
        {
            while (!enc.TryExportEncryptedPkcs8PrivateKey(password,
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA512, 10000),
                encryptionPrivateKeyBytes,
                out cbEncryptionPrivateKey))
            {
                encryptionPrivateKeyBytes = new byte[encryptionPrivateKeyBytes.Length + 100];
            }
        }

        byte[] encryptionPublicKeyBytes = new byte[200];
        int cbEncryptionPublicKey;
        while (!enc.TryExportSubjectPublicKeyInfo(encryptionPublicKeyBytes, out cbEncryptionPublicKey))
        {
            encryptionPublicKeyBytes = new byte[encryptionPrivateKeyBytes.Length + 100];
        }

        using ECDsa sign = ECDsa.Create();
        byte[] signingPrivateKeyBytes = new byte[200];
        int cbSigningPrivateKey;
        if (password.IsEmpty)
        {
            while (!sign.TryExportPkcs8PrivateKey(signingPrivateKeyBytes, out cbSigningPrivateKey))
            {
                signingPrivateKeyBytes = new byte[signingPrivateKeyBytes.Length + 100];
            }
        }
        else
        {
            while (!sign.TryExportEncryptedPkcs8PrivateKey(password,
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA512, 10000),
                signingPrivateKeyBytes,
                out cbSigningPrivateKey))
            {
                signingPrivateKeyBytes = new byte[signingPrivateKeyBytes.Length + 100];
            }
        }

        byte[] signingPublicKeyBytes = new byte[200];
        int cbSigningPublicKey;
        while (!sign.TryExportSubjectPublicKeyInfo(signingPublicKeyBytes, out cbSigningPublicKey))
        {
            signingPublicKeyBytes = new byte[signingPublicKeyBytes.Length + 100];
        }

        privateInfo = new PrivateClientInfo(
            encryptionPrivateKeyBytes.AsMemory(0, cbEncryptionPrivateKey),
            signingPrivateKeyBytes.AsMemory(0, cbSigningPrivateKey)
        );
        publicInfo = new PublicClientInfo(
            encryptionPublicKeyBytes.AsMemory(0, cbEncryptionPublicKey),
            signingPublicKeyBytes.AsMemory(0, cbSigningPublicKey)
        );
    }
}