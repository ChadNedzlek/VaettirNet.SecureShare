using System;
using System.Buffers;
using System.Security.Cryptography;
using VaettirNet.SecureShare.Common;

namespace VaettirNet.SecureShare.Crypto;

public class VaultCryptographyAlgorithm
{
    private ArrayPool<byte> _pool;

    public VaultCryptographyAlgorithm() : this(ArrayPool<byte>.Shared)
    {
    }

    public VaultCryptographyAlgorithm(ArrayPool<byte> arrayPool)
    {
        _pool = arrayPool;
    }

    public bool TryEncryptFor(
        ReadOnlySpan<byte> plainText,
        PrivateKeyInfo privateInfo,
        PublicKeyInfo forPublicInfo,
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
        PrivateKeyInfo privateInfo,
        PublicKeyInfo fromKeyInfo,
        Span<byte> plainText,
        out int bytesWritten
    )
    {
        using Aes aes = Aes.Create();

        using ECDiffieHellman self = ECDiffieHellman.Create();
        self.ImportPkcs8PrivateKey(privateInfo.EncryptionKey.Span, out _);

        using ECDiffieHellman other = ECDiffieHellman.Create();
        other.ImportSubjectPublicKeyInfo(fromKeyInfo.EncryptionKey.Span, out _);
        using ECDiffieHellmanPublicKey otherPublicKeyHandle = other.PublicKey;
        byte[] key = self.DeriveKeyMaterial(otherPublicKeyHandle);

        aes.Key = key;
        ReadOnlySpan<byte> iv = encrypted.Slice(0, aes.BlockSize / 8);
        ReadOnlySpan<byte> cipherText = encrypted.Slice(iv.Length);
        return aes.TryDecryptCbc(cipherText, iv, plainText, out bytesWritten);
    }

    public void CreateKeys(Guid clientId, out PrivateKeyInfo privateInfo, out PublicKeyInfo publicInfo)
    {
        using ECDiffieHellman enc = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using RentedSpan<byte> encryptionPrivateBytes = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => enc.TryExportPkcs8PrivateKey(span, out cb),
            _pool
        );
        
        using RentedSpan<byte> encryptionPublicKeyBytes = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => enc.TryExportSubjectPublicKeyInfo(span, out cb),
            ArrayPool<byte>.Shared
        );

        using ECDsa sign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using RentedSpan<byte> signingPrivateKeyBytes = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => sign.TryExportPkcs8PrivateKey(span, out cb),
            ArrayPool<byte>.Shared
        );

        using RentedSpan<byte> signingPublicKey = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => sign.TryExportSubjectPublicKeyInfo(span, out cb),
            ArrayPool<byte>.Shared
        );

        privateInfo = new PrivateKeyInfo(
            clientId,
            encryptionPrivateBytes.Span.ToArray(),
            signingPrivateKeyBytes.Span.ToArray()
        );
        publicInfo = new PublicKeyInfo(
            clientId,
            encryptionPublicKeyBytes.Span.ToArray(),
            signingPublicKey.Span.ToArray()
        );
    }

    public Validated<T> Sign<T>(T toSign, PrivateKeyInfo privateInfo) where T : ISignable
    {
        using RentedSpan<byte> data = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => toSign.TryGetDataToSign(span, out cb),
            ArrayPool<byte>.Shared);

        byte[] signature = GetSignatureForByteArray(privateInfo, data.Span);
        return Validated.AssertValid(Signed.Create(toSign, privateInfo.Id, signature));
    }

    public byte[] GetSignatureForByteArray(PrivateKeyInfo privateInfo, Span<byte> data)
    {
        ECDsa dsa = ECDsa.Create();
        dsa.ImportPkcs8PrivateKey(privateInfo.SigningKey.Span, out _);
        byte[] signature = dsa.SignData(data, HashAlgorithmName.SHA256);
        return signature;
    }

    public bool TryValidate<T>(Signed<T> signed, PublicKeyInfo publicInfo, out Validated<T> validated) where T : ISignable
    {
        T unvalidated = signed.DangerousGetPayload();
        
        ECDsa dsa = ECDsa.Create();
        dsa.ImportSubjectPublicKeyInfo(publicInfo.SigningKey.Span, out _);

        using RentedSpan<byte> data = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => unvalidated.TryGetDataToSign(span, out cb),
            ArrayPool<byte>.Shared);

        if (!dsa.VerifyData(data.Span, signed.Signature.Span, HashAlgorithmName.SHA256))
        {
            validated = default;
            return false;
        }

        validated = Validated<T>.AssertValid(signed);
        return true;
    }

    public bool TryValidate<T>(Signed<T> signed, ReadOnlySpan<byte> publicKey, out Validated<T> payload) where T : ISignable
    {
        T unvalidated = signed.DangerousGetPayload();
        
        ECDsa dsa = ECDsa.Create();
        dsa.ImportSubjectPublicKeyInfo(publicKey, out _);

        using RentedSpan<byte> data = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => unvalidated.TryGetDataToSign(span, out cb),
            ArrayPool<byte>.Shared);

        if (!dsa.VerifyData(data.Span, signed.Signature.Span, HashAlgorithmName.SHA256))
        {
            payload = default;
            return false;
        }

        payload = Validated.AssertValid(signed);
        return true;
    }

    public T GetPayload<T>(Signed<T> signed, PublicKeyInfo publicInfo) where T : ISignable
    {
        if (!TryValidate(signed, publicInfo, out Validated<T> payload))
        {
            throw new ArgumentException("Signed is not validly signed by signer");
        }

        return payload;
    }

    public PublicKeyInfo GetPublic(PrivateKeyInfo privateInfo)
    {
        using ECDiffieHellman encryption = ECDiffieHellman.Create();
        encryption.ImportPkcs8PrivateKey(privateInfo.EncryptionKey.Span, out _);
        using ECDsa signing = ECDsa.Create();
        signing.ImportPkcs8PrivateKey(privateInfo.SigningKey.Span, out _);
        
        using RentedSpan<byte> signingPublicKey = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => signing.TryExportSubjectPublicKeyInfo(span, out cb),
            ArrayPool<byte>.Shared
        );
        using RentedSpan<byte> encryptionPublicKey = SpanHelpers.GrowingSpan(
            stackalloc byte[200],
            (Span<byte> span, out int cb) => encryption.TryExportSubjectPublicKeyInfo(span, out cb),
            ArrayPool<byte>.Shared
        );

        return new PublicKeyInfo(privateInfo.Id, encryptionPublicKey.Span.ToArray(), signingPublicKey.Span.ToArray());
    }
}