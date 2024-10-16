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
        VaultManager aliceVaultManager = VaultManager.Initialize("Alice", out PrivateClientInfo aliceInfo);
        aliceVaultManager.Vault.Data.TryGetClient(aliceVaultManager.Vault.ClientId, out VaultClientEntry aliceEntry).Should().BeTrue();
        aliceEntry.Description.Should().Be("Alice");
        Guid secretId;
        {
            UnsealedVault unsealed = aliceVaultManager.Unseal();
            SecretStore<SecretAttributes, SecretProtectedValue> store = unsealed.GetOrCreateStore<SecretAttributes, SecretProtectedValue>();
            secretId = store.Add(new() { Value = "Attr Value" }, new() { ProtValue = "Test Value" });
            unsealed.SaveStore(store);
        }

        VaultCryptographyAlgorithm messageAlg = new();
        VaultRequestManager vaultRequestManager = new(messageAlg);
        VaultRequest bobRequest = vaultRequestManager.CreateRequest("Bob's Client", out PrivateClientInfo bobPrivateInfo);

        aliceVaultManager.AddAuthenticatedClient(aliceInfo, bobRequest);
        aliceVaultManager.Vault.Data.TryGetClient(bobRequest.ClientId, out VaultClientEntry bobEntry).Should().BeTrue();
        bobEntry.Description.Should().Be("Bob's Client");
        bobEntry.EncryptionKey.Should().BeEquivalentTo(bobRequest.EncryptionKey);

        VaultManager bobManager = VaultManager.Import(messageAlg, new SealedVault(aliceVaultManager.Vault.Data, bobRequest.ClientId), bobPrivateInfo);
        {
            UnsealedVault unsealed = bobManager.Unseal();
            SecretStore<SecretAttributes, SecretProtectedValue> store = unsealed.GetOrCreateStore<SecretAttributes, SecretProtectedValue>();
            UnsealedSecretValue<SecretAttributes, SecretProtectedValue> secret = store.GetUnsealed(secretId);
            secret.Attributes.Value.Should().Be("Attr Value");
            secret.Protected.ProtValue.Should().Be("Test Value");
        }
    }
}