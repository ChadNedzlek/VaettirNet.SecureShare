using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare;

public class VaultCryptographyAlgorithm
{
    public bool TryEncryptFor(
        ReadOnlySpan<byte> plainText,
        PrivateClientInfo privateInfo,
        PublicClientInfo forPublicInfo,
        Span<byte> encrypted,
        out int bytesWritten
    )
    {
        using Aes aes = Aes.Create();
        bytesWritten = plainText.Length + 2 * (aes.BlockSize / 8) - plainText.Length % (aes.BlockSize / 8);
        if (bytesWritten > encrypted.Length) return false;

        using ECDiffieHellman self = ECDiffieHellman.Create();
        self.ImportPkcs8PrivateKey(privateInfo.EncryptionKey.Span, out _);

        using ECDiffieHellman other = ECDiffieHellman.Create();
        other.ImportSubjectPublicKeyInfo(forPublicInfo.EncryptionKey.Span, out _);
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
        PrivateClientInfo privateInfo,
        PublicClientInfo fromClientInfo,
        Span<byte> plainText,
        out int bytesWritten
    )
    {
        using Aes aes = Aes.Create();

        using ECDiffieHellman self = ECDiffieHellman.Create();
        self.ImportPkcs8PrivateKey(privateInfo.EncryptionKey.Span, out _);

        using ECDiffieHellman other = ECDiffieHellman.Create();
        other.ImportSubjectPublicKeyInfo(fromClientInfo.EncryptionKey.Span, out _);
        using ECDiffieHellmanPublicKey otherPublicKeyHandle = other.PublicKey;
        byte[] key = self.DeriveKeyMaterial(otherPublicKeyHandle);

        aes.Key = key;
        ReadOnlySpan<byte> iv = encrypted.Slice(0, aes.BlockSize / 8);
        ReadOnlySpan<byte> cipherText = encrypted.Slice(iv.Length);
        return aes.TryDecryptCbc(cipherText, iv, plainText, out bytesWritten);
    }

    public void Create(Guid clientId, out PrivateClientInfo privateInfo, out PublicClientInfo publicInfo)
    {
        using ECDiffieHellman enc = ECDiffieHellman.Create();
        using RentedSpan<byte> encryptionPrivateBytes = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => enc.TryExportPkcs8PrivateKey(span, out cb),
            VaultArrayPool.Pool
        );
        
        using RentedSpan<byte> encryptionPublicKeyBytes = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => enc.TryExportSubjectPublicKeyInfo(span, out cb),
            VaultArrayPool.Pool
        );

        using ECDsa sign = ECDsa.Create();
        using RentedSpan<byte> signingPrivateKeyBytes = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => sign.TryExportPkcs8PrivateKey(span, out cb),
            VaultArrayPool.Pool
        );

        using RentedSpan<byte> signingPublicKey = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => sign.TryExportSubjectPublicKeyInfo(span, out cb),
            VaultArrayPool.Pool
        );

        privateInfo = new PrivateClientInfo(
            clientId,
            encryptionPrivateBytes.Span.ToArray(),
            signingPrivateKeyBytes.Span.ToArray()
        );
        publicInfo = new PublicClientInfo(
            clientId,
            encryptionPublicKeyBytes.Span.ToArray(),
            signingPublicKey.Span.ToArray()
        );
    }

    public Signed<T> Sign<T>(T toSign, PrivateClientInfo privateInfo) where T : ISignable
    {
        using RentedSpan<byte> data = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => toSign.TryGetDataToSign(span, out cb),
            VaultArrayPool.Pool);

        byte[] signature = GetSignatureForByteArray(privateInfo, data.Span);
        return Signed.Create(toSign, privateInfo.ClientId, signature);
    }

    public byte[] GetSignatureForByteArray(PrivateClientInfo privateInfo, Span<byte> data)
    {
        var dsa = ECDsa.Create();
        dsa.ImportPkcs8PrivateKey(privateInfo.SigningKey.Span, out _);
        byte[] signature = dsa.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return signature;
    }

    public bool TryGetPayload<T>(Signed<T> toSign, PublicClientInfo publicInfo, [MaybeNullWhen(false)] out T payload) where T : ISignable
    {
        T unvalidated = toSign.DangerousGetPayload();
        
        var dsa = ECDsa.Create();
        dsa.ImportSubjectPublicKeyInfo(publicInfo.SigningKey.Span, out _);

        using RentedSpan<byte> data = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => unvalidated.TryGetDataToSign(span, out cb),
            VaultArrayPool.Pool);

        if (!dsa.VerifyData(data.Span, toSign.Signature.Span, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
        {
            payload = default;
            return false;
        }

        payload = unvalidated;
        return true;
    }

    public PublicClientInfo GetPublic(PrivateClientInfo privateInfo)
    {
        using ECDiffieHellman encryption = ECDiffieHellman.Create();
        encryption.ImportPkcs8PrivateKey(privateInfo.EncryptionKey.Span, out _);
        using ECDsa signing = ECDsa.Create();
        signing.ImportPkcs8PrivateKey(privateInfo.SigningKey.Span, out _);
        
        using RentedSpan<byte> signingPublicKey = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => signing.TryExportSubjectPublicKeyInfo(span, out cb),
            VaultArrayPool.Pool
        );
        using RentedSpan<byte> encryptionPublicKey = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => encryption.TryExportSubjectPublicKeyInfo(span, out cb),
            VaultArrayPool.Pool
        );

        return new PublicClientInfo(privateInfo.ClientId, encryptionPublicKey.Span.ToArray(), signingPublicKey.Span.ToArray());
    }
}