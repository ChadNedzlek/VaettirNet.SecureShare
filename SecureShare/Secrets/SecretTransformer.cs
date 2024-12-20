using System;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using JetBrains.Annotations;
using VaettirNet.SecureShare.Common;
using VaettirNet.SecureShare.Serialization;

using DataProtectionScope = VaettirNet.Cryptography.DataProtectionScope;
using ProtectedData = VaettirNet.Cryptography.ProtectedData;

namespace VaettirNet.SecureShare.Secrets;

public class SecretTransformer
{
    public static readonly int KeySizeInBytes = 256 / 8;

    private readonly ConcurrentBag<Aes> _encryptors = new();

    private readonly ImmutableArray<byte> _protectedKey;

    private SecretTransformer(ImmutableArray<byte> protectedKey, int keySize)
    {
        _protectedKey = protectedKey;
        KeySize = keySize;
    }

    public int KeySize { get; }
    public uint Version => 1;
    public int CurrentKeyId { get; } = 1;

    public static SecretTransformer CreateRandom()
    {
        Span<byte> key = stackalloc byte[KeySizeInBytes];
        Span<byte> protectedKey = stackalloc byte[300];
        RandomNumberGenerator.Fill(key);
        SetKey(key, protectedKey, out int cb);
        return new SecretTransformer(protectedKey[..cb].ToImmutableArray(), KeySizeInBytes);
    }

    public static SecretTransformer CreateFromSharedKey(ReadOnlySpan<byte> sharedKey)
    {
        Span<byte> protectedKey = stackalloc byte[300];
        SetKey(sharedKey, protectedKey, out int cb);
        return new SecretTransformer(protectedKey[..cb].ToImmutableArray(), sharedKey.Length);
    }

    [MustDisposeResource]
    private Encryptor GetAlgorithm()
    {
        if (!_encryptors.TryTake(out Aes aes))
        {
            Span<byte> key = stackalloc byte[KeySize];
            GetKey(key, out int cb);
            aes = Aes.Create();
            aes.Key = key[..cb].ToArray();
            key.Clear();
        }

        return new Encryptor(_encryptors, aes);
    }

    private void GetKey(Span<byte> key, out int bytesWritten)
    {
        if (OperatingSystem.IsWindows())
        {
            ProtectedData.Unprotect(_protectedKey.AsSpan(), default, key, DataProtectionScope.CurrentUser, out bytesWritten);
        }
        else
        {
            _protectedKey.CopyTo(key);
            bytesWritten = key.Length;
        }
    }

    private static void SetKey(ReadOnlySpan<byte> key, Span<byte> protectedKey, out int bytesWritten)
    {
        if (OperatingSystem.IsWindows())
        {
            ProtectedData.Protect(key, default, protectedKey, DataProtectionScope.CurrentUser, out bytesWritten);
        }
        else
        {
            key.CopyTo(protectedKey);
            bytesWritten = key.Length;
        }
    }

    private bool TryProtect(ReadOnlySpan<byte> input, Span<byte> destination, out int cb)
    {
        using Encryptor enc = GetAlgorithm();
        return enc.TryEncrypt(input, destination, out cb);
    }

    private bool TryUnprotect(ReadOnlySpan<byte> input, int keyId, Span<byte> destination, out int cb)
    {
        if (keyId != CurrentKeyId)
            throw new NotSupportedException($"Expected version {Version} with key id {CurrentKeyId}");

        using Encryptor enc = GetAlgorithm();
        return enc.TryDecrypt(input, destination, out cb);
    }

    public UnsealedSecret<TAttributes, TProtected> Unseal<TAttributes, TProtected>(
        SealedSecret<TAttributes, TProtected> secret
    ) where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes> where TProtected : IBinarySerializable<TProtected>
    {
        return UnsealInternal(secret);
    }

    private UnsealedSecret<TAttributes, TProtected> UnsealInternal<TAttributes, TProtected>(
        SealedSecret<TAttributes, TProtected> secret
    ) where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
        where TProtected : IBinarySerializable<TProtected>
    {
        using RentedSpan<byte> decryptedValue = SpanHelpers.GrowingSpan(
            stackalloc byte[100],
            (Span<byte> s, out int cb) => TryUnprotect(secret.Protected.Span, secret.KeyId, s, out cb),
            VaultArrayPool.Pool);

        return new (secret.Id, secret.Attributes, TProtected.GetBinarySerializer().Deserialize(decryptedValue.Span));
    }

    public SealedSecret<TAttributes, TProtected> Seal<TAttributes, TProtected>(
        UnsealedSecret<TAttributes, TProtected> secret
    ) where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes> where TProtected : IBinarySerializable<TProtected>
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> stackBuffer = stackalloc byte[50];
        using RentedSpan<byte> attr = SpanHelpers.GrowingSpan(stackBuffer,
            (Span<byte> s, out int cb) => TAttributes.GetBinarySerializer().TrySerialize(secret.Attributes, s, out cb),
            VaultArrayPool.Pool);
        hash.AppendData(MemoryMarshal.AsBytes([attr.Span.Length]));
        hash.AppendData(attr.Span);
        
        using RentedSpan<byte> serialized = SpanHelpers.GrowingSpan(stackBuffer,
            (Span<byte> s, out int cb) => TProtected.GetBinarySerializer().TrySerialize(secret.Protected, s, out cb),
            VaultArrayPool.Pool);
        hash.AppendData(MemoryMarshal.AsBytes([serialized.Span.Length]));
        hash.AppendData(serialized.Span);
        
        Memory<byte> hashBytes = new byte[SHA256.HashSizeInBytes];
        if (!hash.TryGetHashAndReset(hashBytes.Span, out int cbHash) || cbHash != SHA256.HashSizeInBytes)
        {
            throw new InvalidOperationException();
        }

        using RentedSpan<byte> encrypted = SpanHelpers.GrowingSpan(
            stackalloc byte[50],
            serialized.Span,
            (Span<byte> s, ReadOnlySpan<byte> e, out int cb) => TryProtect(e, s, out cb),
            VaultArrayPool.Pool);
        
        return SealedSecret.Create<TAttributes, TProtected>(secret.Id, secret.Attributes, encrypted.Span.ToArray(), CurrentKeyId, hashBytes, Version);
    }

    public void ExportKey(Span<byte> sharedKey, out int bytesWritten)
    {
        GetKey(sharedKey, out bytesWritten);
    }

    private readonly ref struct Encryptor
    {
        private readonly ConcurrentBag<Aes> _pool;
        private readonly Aes _alg;

        public Encryptor(ConcurrentBag<Aes> pool, Aes alg)
        {
            _pool = pool;
            _alg = alg;
        }

        public bool TryEncrypt(ReadOnlySpan<byte> plainText, Span<byte> output, out int cb)
        {
            Span<byte> iv = output.Slice(0, _alg.BlockSize / 8);
            Span<byte> cipherText = output.Slice(_alg.BlockSize / 8);
            RandomNumberGenerator.Fill(iv);
            if (_alg.TryEncryptCbc(plainText, iv, cipherText, out int cbCipher))
            {
                cb = cbCipher + iv.Length;
                return true;
            }

            cb = 0;
            return false;
        }

        public bool TryDecrypt(ReadOnlySpan<byte> input, Span<byte> plainText, out int cb)
        {
            ReadOnlySpan<byte> iv = input.Slice(0, _alg.BlockSize / 8);
            ReadOnlySpan<byte> cipherText = input.Slice(_alg.BlockSize / 8);
            return _alg.TryDecryptCbc(cipherText, iv, plainText, out cb);
        }

        public void Dispose()
        {
            if (_pool.Count < 10)
                _pool.Add(_alg);
        }
    }
}