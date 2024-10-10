using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using JetBrains.Annotations;
using DataProtectionScope = VaettirNet.Cryptography.DataProtectionScope;
using ProtectedData = VaettirNet.Cryptography.ProtectedData;

namespace SecureShare;

public class SecretTransformer
{
    private static readonly int s_keySizeInBytes = 256 / 8;

    private readonly ArrayPool<byte> _arrayPool = ArrayPool<byte>.Create();

    private readonly ConcurrentBag<Aes> _encryptors = new();

    private readonly ImmutableArray<byte> _protectedKey;

    private SecretTransformer(ImmutableArray<byte> protectedKey, int keySize)
    {
        _protectedKey = protectedKey;
        KeySize = keySize;
    }

    public int KeySize { get; }
    public int Version => 1;
    public int CurrentKeyId { get; } = 1;

    public static SecretTransformer CreateRandom()
    {
        Span<byte> key = stackalloc byte[s_keySizeInBytes];
        Span<byte> protectedKey = stackalloc byte[300];
        RandomNumberGenerator.Fill(key);
        SetKey(key, protectedKey, out int cb);
        return new SecretTransformer(protectedKey[..cb].ToImmutableArray(), s_keySizeInBytes);
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
        if (!_encryptors.TryTake(out Aes? aes))
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

    private bool TryUnprotect(ReadOnlySpan<byte> input, int keyId, int version, Span<byte> destination, out int cb)
    {
        if (keyId != CurrentKeyId || version != Version)
            throw new NotSupportedException($"Expected version {Version} with key id {CurrentKeyId}");

        using Encryptor enc = GetAlgorithm();
        return enc.TryDecrypt(input, destination, out cb);
    }

    public UntypedSecret<TAttributes> Unseal<TAttributes>(
        SealedSecretValue<TAttributes> secret
    )
    {
        return new PooledUntypedSecret<TAttributes>(this, secret);
    }

    public UnsealedSecretValue<TAttributes, TProtected> Unseal<TAttributes, TProtected>(
        SealedSecretValue<TAttributes, TProtected> value
    )
    {
        return UnsealInternal<TAttributes, TProtected>(value);
    }

    private UnsealedSecretValue<TAttributes, TProtected> UnsealInternal<TAttributes, TProtected>(
        SealedSecretValue<TAttributes> value
    )
    {
        using RentedSpan<byte> decryptedValue = Helpers.GrowingSpan(
            stackalloc byte[100],
            (Span<byte> s, out int cb) => TryUnprotect(value.Protected.AsSpan(), value.KeyId, value.Version, s, out cb),
            VaultArrayPool.Pool);

        var ret = new UnsealedSecretValue<TAttributes, TProtected>(value.Id,
            value.Attributes,
            JsonSerializer.Deserialize<TProtected>(decryptedValue.Span)!
        );

        stackalloc byte[100].Clear();

        return ret;
    }

    public SealedSecretValue<TAttributes, TProtected> Seal<TAttributes, TProtected>(
        UnsealedSecretValue<TAttributes, TProtected> secret
    )
    {
        var buffer = new ArrayBufferWriter<byte>();
        Utf8JsonWriter writer = new(buffer);
        JsonSerializer.Serialize(writer, secret.Protected);
        using RentedSpan<byte> data = Helpers.GrowingSpan(
            stackalloc byte[50],
            (Span<byte> s, out int cb) => TryProtect(buffer.WrittenSpan, s, out cb),
            VaultArrayPool.Pool);
        
        return new SealedSecretValue<TAttributes, TProtected>(secret.Id, secret.Attributes, data.Span.ToImmutableArray(), CurrentKeyId, Version);
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

    public abstract class UntypedSecret<TAttributes>
    {
        protected readonly SealedSecretValue<TAttributes> Value;

        public UntypedSecret(SealedSecretValue<TAttributes> value)
        {
            Value = value;
        }

        public abstract UnsealedSecretValue<TAttributes, TProtected> As<TProtected>();
    }

    private class PooledUntypedSecret<TAttributes> : UntypedSecret<TAttributes>
    {
        private readonly SecretTransformer _transformer;

        public PooledUntypedSecret(SecretTransformer transformer, SealedSecretValue<TAttributes> value) : base(value)
        {
            _transformer = transformer;
        }

        public override UnsealedSecretValue<TAttributes, TProtected> As<TProtected>()
        {
            return _transformer.UnsealInternal<TAttributes, TProtected>(Value);
        }
    }
}