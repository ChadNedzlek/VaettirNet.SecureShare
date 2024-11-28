using System;
using System.Collections.Immutable;
using VaettirNet.SecureShare.Crypto;

namespace VaettirNet.TreeFormat;

public readonly struct TrustedPublicKeys
{
    public static readonly TrustedPublicKeys None = new(ImmutableDictionary<Guid, PublicKeyInfo>.Empty);

    private readonly ImmutableDictionary<Guid, PublicKeyInfo> _trusted;
    private ImmutableDictionary<Guid, PublicKeyInfo> Trusted => _trusted ?? ImmutableDictionary<Guid, PublicKeyInfo>.Empty;

    private TrustedPublicKeys(ImmutableDictionary<Guid, PublicKeyInfo> trusted)
    {
        _trusted = trusted;
    }

    public TrustedPublicKeys With(PublicKeyInfo info)
    {
        return new TrustedPublicKeys(Trusted.Add(info.Id, info));
    }

    public TrustedPublicKeys Without(PublicKeyInfo info)
    {
        return Without(info.Id);
    }

    public TrustedPublicKeys Without(Guid id)
    {
        return new TrustedPublicKeys(Trusted.Remove(id));
    }

    public TrustedPublicKeys WithUpdated(PublicKeyInfo info)
    {
        return new TrustedPublicKeys(Trusted.SetItem(info.Id, info));
    }

    public bool TryGet(Guid id, out PublicKeyInfo info)
    {
        return Trusted.TryGetValue(id, out info);
    }

    public PublicKeyInfo Get(Guid id)
    {
        if (!TryGet(id, out PublicKeyInfo value))
            throw new SignatureValidationFailedException($"Singing keys not found for {id}");
        return value;
    }
}