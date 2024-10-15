using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using VaettirNet.SecureShare;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Vaults;

// ReSharper disable PossibleNullReferenceException

namespace SecureShare.Tests;

public class VaultTest
{
    [Test]
    public void SealUnseal()
    {
        var aliceVaultManager = VaultManager.Initialize("Alice", out var aliceInfo);
        aliceVaultManager.Vault.Data.TryGetClient(aliceVaultManager.Vault.ClientId, out VaultClientEntry aliceEntry).Should().BeTrue();
        aliceEntry.Description.Should().Be("Alice");
        aliceEntry.AuthorizedByClientId.Should().Be(aliceVaultManager.Vault.ClientId);
        Guid secretId;
        {
            UnsealedVault unsealed = aliceVaultManager.Unseal();
            SecretStore<SecretAttributes, SecretProtectedValue> store = unsealed.GetOrCreateStore<SecretAttributes, SecretProtectedValue>();
            secretId = store.Add(new() { Value = "Attr Value" }, new() { ProtValue = "Test Value" });
            unsealed.SaveStore(store);
        }

        VaultCryptographyAlgorithm messageAlg = new();
        VaultRequestManager vaultRequestManager = new(messageAlg);
        var bobRequest = vaultRequestManager.CreateRequest("Bob's Client", out var bobPrivateInfo);

        aliceVaultManager.AddAuthenticatedClient(aliceInfo.EncryptionKey.Span, bobRequest);
        aliceVaultManager.Vault.Data.TryGetClient(bobRequest.ClientId, out VaultClientEntry bobEntry).Should().BeTrue();
        bobEntry.Description.Should().Be("Bob's Client");
        bobEntry.AuthorizedByClientId.Should().Be(aliceVaultManager.Vault.ClientId);
        bobEntry.EncryptionKey.Should().BeEquivalentTo(bobRequest.EncryptionKey);

        VaultManager bobManager = VaultManager.Import(messageAlg, new SealedVault(aliceVaultManager.Vault.Data, bobRequest.ClientId), bobPrivateInfo.EncryptionKey.Span);
        {
            UnsealedVault unsealed = bobManager.Unseal();
            SecretStore<SecretAttributes, SecretProtectedValue> store = unsealed.GetOrCreateStore<SecretAttributes, SecretProtectedValue>();
            var secret = store.GetUnsealed(secretId);
            secret.Attributes.Value.Should().Be("Attr Value");
            secret.Protected.ProtValue.Should().Be("Test Value");
        }
    }
}