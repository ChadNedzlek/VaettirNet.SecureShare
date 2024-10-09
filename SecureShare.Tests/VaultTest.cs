using FluentAssertions;

namespace SecureShare.Tests;

public class VaultTest
{
    [Test]
    public void SealUnseal()
    {
        Guid aliceId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        Guid bobId = Guid.Parse("11111111-1111-1111-1111-111111111111");

        Span<byte> alicePrivateKey = stackalloc byte[250];
        VaultManager.TryInitialize(alicePrivateKey, out var aliceCb, out VaultManager? aliceVaultManager)
            .Should()
            .BeTrue();
        
        Span<byte> bobPrivateKey = stackalloc byte[250];
        VaultManager.TryPrepareForImport(aliceVaultManager.AsSealed().Data, bobPrivateKey, out var bobCb, out var bobSealedVault)
            .Should()
            .BeTrue();;

        Span<byte> message = stackalloc byte[500];
        aliceVaultManager.TryGetShareKey(bobSealedVault.ClientId,
                alicePrivateKey[..aliceCb],
                message,
                out var messageCb)
            .Should()
            .BeTrue();

        VaultManager bobVaultManager = VaultManager.Import(bobSealedVault, bobPrivateKey[..bobCb], message[..messageCb]);
    }
}