using FluentAssertions;
// ReSharper disable PossibleNullReferenceException

namespace SecureShare.Tests;

public class VaultTest
{
    [Test]
    public void SealUnseal()
    {
        Span<byte> alicePrivateKey = stackalloc byte[250];
        VaultManager.TryInitialize("Alice", alicePrivateKey, out int aliceCb, out VaultManager aliceVaultManager)
            .Should()
            .BeTrue();
        aliceVaultManager.Vault.Data.TryGetClient(aliceVaultManager.Vault.ClientId, out VaultClientEntry aliceEntry).Should().BeTrue();
        aliceEntry.Description.Should().Be("Alice");
        aliceEntry.AuthorizedByClientId.Should().Be(aliceVaultManager.Vault.ClientId);
        Guid secretId;
        {
            UnsealedVault unsealed = aliceVaultManager.Unseal();
            SecretStore<int, string> store = unsealed.GetOrCreateStore<int, string>();
            secretId = store.Add(5, "Test Value");
            unsealed.SaveStore(store);
        }

        Span<byte> bobPrivateKey = stackalloc byte[250];
        MessageEncryptionAlgorithm messageAlg = new();
        VaultRequestManager vaultRequestManager = new(messageAlg);
        vaultRequestManager.TryCreateRequest("Bob's Client", bobPrivateKey, out int cbBob, out VaultRequest bobRequest)
            .Should()
            .BeTrue();

        aliceVaultManager.AddAuthenticatedClient(alicePrivateKey[..aliceCb], bobRequest);
        aliceVaultManager.Vault.Data.TryGetClient(bobRequest.ClientId, out VaultClientEntry bobEntry).Should().BeTrue();
        bobEntry.Description.Should().Be("Bob's Client");
        bobEntry.AuthorizedByClientId.Should().Be(aliceVaultManager.Vault.ClientId);
        bobEntry.PublicKey.Should().BeEquivalentTo(bobRequest.PublicKey);

        VaultManager bobManager = VaultManager.Import(messageAlg, new SealedVault(aliceVaultManager.Vault.Data, bobRequest.ClientId), bobPrivateKey[..cbBob]);
        {
            UnsealedVault unsealed = bobManager.Unseal();
            SecretStore<int, string> store = unsealed.GetOrCreateStore<int, string>();
            var secret = store.GetUnsealed(secretId);
            secret.Attributes.Should().Be(5);
            secret.Protected.Should().Be("Test Value");
        }
    }
}