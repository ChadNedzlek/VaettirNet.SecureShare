using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace SecureShare;

public class MessageEncryptionAlgorithm
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

    public bool TryCreate(Span<byte> privateKey, out int cbPrivate, Span<byte> publicKey, out int cbPublic)
    {
        return TryCreate(default, privateKey, out cbPrivate, publicKey, out cbPublic);
    }

    public bool TryCreate(ReadOnlySpan<char> password, Span<byte> privateKey, out int cbPrivate, Span<byte> publicKey, out int cbPublic)
    {
        using ECDiffieHellman ecc = ECDiffieHellman.Create();
        if (password.IsEmpty)
        {
            if (!ecc.TryExportPkcs8PrivateKey(privateKey, out cbPrivate))
            {
                cbPublic = 0;
                return false;
            }
        }
        else
        {
            if (!ecc.TryExportEncryptedPkcs8PrivateKey(password,
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA512, 10000),
                privateKey,
                out cbPrivate))
            {
                cbPublic = 0;
                return false;
            }
        }

        using ECDiffieHellmanPublicKey publicKeyHandle = ecc.PublicKey;
        return publicKeyHandle.TryExportSubjectPublicKeyInfo(publicKey, out cbPublic);
    }
}