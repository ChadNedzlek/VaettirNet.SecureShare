using System.Buffers;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using JetBrains.Annotations;

namespace SecureShare;

public class SecretTransformer
{
    private static readonly int KeySizeInBytes = 256 / 8;
    private static readonly int NonceSizeInBytes = AesGcm.NonceByteSizes.MaxSize;
    private static readonly int TagSizeInBytes = AesGcm.TagByteSizes.MaxSize;

    private readonly byte[] _protectedKey;

    private SecretTransformer(byte[] protectedKey)
    {
        _protectedKey = protectedKey;
        KeySize = _protectedKey.Length;
    }

    public int KeySize { get; }
    public int Version => 1;
    public int CurrentKeyId { get; } = 1;

    private readonly ConcurrentBag<AesGcm> _encryptors = new();

    public static SecretTransformer CreateRandom()
    {
        byte[] key = new byte[KeySizeInBytes];
        RandomNumberGenerator.Fill(key);
        return new SecretTransformer(SetKey(key));
    }

    public static SecretTransformer CreateFromSharedKey(ReadOnlySpan<byte> sharedKey)
    {
        return new SecretTransformer(SetKey(sharedKey.ToArray()));
    }

    [MustDisposeResource]
    private Encryptor GetAlgorithm()
    {
        if (!_encryptors.TryTake(out AesGcm? aesGcm))
        {
            Span<byte> key = GetKey();
            aesGcm = new AesGcm(key, TagSizeInBytes);
            key.Clear();
        }

        return new Encryptor(_encryptors, aesGcm);
    }

    private Span<byte> GetKey()
    {
        if (OperatingSystem.IsWindows()) return ProtectedData.Unprotect(_protectedKey, null, DataProtectionScope.CurrentUser);

        return _protectedKey;
    }

    private static byte[] SetKey(byte[] key)
    {
        if (OperatingSystem.IsWindows()) return ProtectedData.Protect(key, null, DataProtectionScope.CurrentUser);

        return key;
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

    private readonly ref struct Encryptor
    {
        private readonly ConcurrentBag<AesGcm> _pool;
        private readonly AesGcm _alg;

        public Encryptor(ConcurrentBag<AesGcm> pool, AesGcm alg)
        {
            _pool = pool;
            _alg = alg;
        }

        public bool TryEncrypt(ReadOnlySpan<byte> input, Span<byte> output, out int cb)
        {
            cb = input.Length + TagSizeInBytes + NonceSizeInBytes;
            if (cb > output.Length) return false;

            Span<byte> nonce = output[..12];
            Span<byte> tag = output.Slice(NonceSizeInBytes, TagSizeInBytes);
            Span<byte> cipherText = output.Slice(NonceSizeInBytes + TagSizeInBytes);

            RandomNumberGenerator.Fill(nonce);

            _alg.Encrypt(nonce, input, cipherText, tag);
            return true;
        }

        public bool TryDecrypt(ReadOnlySpan<byte> input, Span<byte> output, out int cb)
        {
            cb = input.Length - NonceSizeInBytes - TagSizeInBytes;
            if (output.Length < cb - TagSizeInBytes)
            {
                return false;
            }

            ReadOnlySpan<byte> nonce = input[..NonceSizeInBytes];
            ReadOnlySpan<byte> tag = input.Slice(NonceSizeInBytes, TagSizeInBytes);
            ReadOnlySpan<byte> cipherText = input.Slice(NonceSizeInBytes + TagSizeInBytes);

            _alg.Decrypt(nonce, cipherText, tag, output[..cb]);
            return true;
        }

        public void Dispose()
        {
            if (_pool.Count < 10)
                _pool.Add(_alg);
        }
    }

    public abstract class UntypedSecret<TAttributes>
    {
        protected readonly ClosedSecretValue<TAttributes> Value;

        public UntypedSecret(ClosedSecretValue<TAttributes> value)
        {
            Value = value;
        }

        public abstract UnsealedSecretValue<TAttributes, TProtected> As<TProtected>();
    }

    private class PooledUntypedSecret<TAttributes> : UntypedSecret<TAttributes>
    {
        private readonly SecretTransformer _transformer;

        public PooledUntypedSecret(SecretTransformer transformer, ClosedSecretValue<TAttributes> value) : base(value)
        {
            _transformer = transformer;
        }

        public override UnsealedSecretValue<TAttributes, TProtected> As<TProtected>() =>
            _transformer.UnsealInternal<TAttributes, TProtected>(Value);
    }
    
    private readonly ArrayPool<byte> _arrayPool = ArrayPool<byte>.Create();

    public UntypedSecret<TAttributes> Unseal<TAttributes>(
        ClosedSecretValue<TAttributes> secret
    ) => new PooledUntypedSecret<TAttributes>(this, secret);

    public UnsealedSecretValue<TAttributes, TProtected> Unseal<TAttributes, TProtected>(
        SealedSecretValue<TAttributes, TProtected> value
    ) => UnsealInternal<TAttributes, TProtected>(value);

    private UnsealedSecretValue<TAttributes, TProtected> UnsealInternal<TAttributes, TProtected>(ClosedSecretValue<TAttributes> value
    )
    {
        Span<byte> rawBytes = stackalloc byte[100];
        byte[]? rented = null;
        if (!TryUnprotect(value.Protected, value.KeyId, value.Version, rawBytes, out int cb))
        {
            rawBytes = rented = _arrayPool.Rent(cb);
            TryUnprotect(value.Protected, value.KeyId, value.Version, rawBytes, out cb);
        }

        var ret = new UnsealedSecretValue<TAttributes, TProtected>(value.Id,
            value.Attributes,
            JsonSerializer.Deserialize<TProtected>(rawBytes[..cb])!
        );

        rawBytes.Clear();

        if (rented != null) _arrayPool.Return(rented);

        return ret;
    }

    public SealedSecretValue<TAttributes, TProtected> Seal<TAttributes, TProtected>(
        UnsealedSecretValue<TAttributes, TProtected> secret
    )
    {
        var buffer = new ArrayBufferWriter<byte>();
        Utf8JsonWriter writer = new(buffer);
        JsonSerializer.Serialize(writer, secret.Protected);
        TryProtect(buffer.WrittenSpan, default, out int cb);
        byte[] data = new byte[cb];
        TryProtect(buffer.WrittenSpan, data, out _);
        return new SealedSecretValue<TAttributes, TProtected>(secret.Id, secret.Attributes, data, CurrentKeyId, Version);
    }

    public void ExportKey(Span<byte> sharedKey)
    {
        GetKey().CopyTo(sharedKey);
    }
}