using System.Diagnostics;
using FluentAssertions;
using ProtoBuf;
using VaettirNet.SecureShare;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Serialization;
using VaettirNet.SecureShare.Vaults;
using VaettirNet.SecureShare.Vaults.Conflict;

namespace SecureShare.Tests;

public class ConflictResolutionTests
{
    private static readonly VaultCryptographyAlgorithm s_algorithm = new();
    private static readonly VaultConflictResolver s_resolver = new(s_algorithm);
    
    private static ClientData s_blocked;
    private static ClientData s_self;
    private static ClientData s_trusted;
    private static ClientData s_bad;
    private static ClientData s_new;
    
    private static SecretTransformer s_transformer;

    private class ClientData
    {
        public Guid Id { get; }
        public string Description { get; }
        public VaultRequest Request { get; }
        public VaultClientEntry Entry { get; }
        public PrivateClientInfo PrivateInfo { get; }
        public BlockedVaultClientEntry Blocked { get; }

        public PublicClientInfo PublicInfo => Entry.PublicInfo;

        private ClientData(
            Guid id,
            string description,
            VaultRequest request,
            VaultClientEntry entry,
            PrivateClientInfo privateInfo,
            BlockedVaultClientEntry blocked
        )
        {
            Id = id;
            Description = description;
            Request = request;
            Entry = entry;
            PrivateInfo = privateInfo;
            Blocked = blocked;
        }

        public static ClientData Create(Guid id, string description, ClientData signClient = null)
        {
            PrivateClientInfo privateInfo;
            PublicClientInfo publicInfo;
            if (signClient == null)
            {
                s_algorithm.Create(id, out privateInfo, out publicInfo);
            }
            else
            {
                privateInfo = signClient.PrivateInfo;
                publicInfo = signClient.PublicInfo;
            }
            
            VaultRequest request = new(id, description, publicInfo.EncryptionKey, publicInfo.SigningKey);
            VaultClientEntry entry = new VaultManager(s_transformer, s_algorithm, new LiveVaultData()).ApproveRequest(new RefSigner(s_algorithm, privateInfo), request);
            BlockedVaultClientEntry blocked = new(id, description, publicInfo.EncryptionKey);

            return new ClientData(id, description, request, entry, privateInfo, blocked);
        }
    }

    [OneTimeSetUp]
    public static void Setup()
    {
        s_transformer = SecretTransformer.CreateRandom();
        s_self = ClientData.Create(Guid.Parse("11111111-1111-1111-1111-111111111111"), "Self");
        s_trusted = ClientData.Create(Guid.Parse("22222222-2222-2222-2222-222222222222"), "Trusted", s_self);
        s_bad = ClientData.Create(Guid.Parse("33333333-3333-3333-3333-333333333333"), "Bad");
        s_new = ClientData.Create(Guid.Parse("44444444-4444-4444-4444-444444444444"), "New Client", s_trusted);
        s_blocked = ClientData.Create(Guid.Parse("55555555-5555-5555-5555-555555555555"), "Blocked Client", s_trusted);
    }

    [Test]
    public void NoChangeConflict()
    {
        var resolution = s_resolver.Resolve(BuildBasicVault(), BuildBasicVault(), BuildBasicVault());
        resolution.Items.Should().BeEmpty();
        s_resolver.TryAutoResolveConflicts(resolution, new RefSigner(s_algorithm, s_new.PrivateInfo), out var snapshot).Should().BeTrue();
        snapshot.TryGetSignerPublicInfo(out var signerInfo).Should().BeTrue();
        signerInfo.ClientId.Should().Be(s_self.Id, because: "no conflict should not resign/modify vault");
    }
    
    [Test]
    public void LocalOnlyModification()
    {
        ValidatedVaultDataSnapshot localVault = BuildBasicVault();
        var id = AddSecret(ref localVault, "Added Secret", "Added Prot", s_self);
        var resolution = s_resolver.Resolve(BuildBasicVault(), BuildBasicVault(), localVault);
        resolution.Items.Should().BeEmpty();
        s_resolver.TryAutoResolveConflicts(resolution, new RefSigner(s_algorithm, s_new.PrivateInfo), out var snapshot).Should().BeTrue();
        snapshot.TryGetSignerPublicInfo(out var signerInfo).Should().BeTrue();
        signerInfo.ClientId.Should().Be(s_self.Id, because: "no conflict should not resign/modify vault");
        (string attributeValue, string protectedValue) = GetSecretValues(snapshot, id);
        attributeValue.Should().Be("Added Secret");
        attributeValue.Should().Be("Added Prot");
    }

    private Guid AddSecret(
        ref ValidatedVaultDataSnapshot input,
        string attributeValue,
        string protectedValue,
        ClientData client
    ) => AddSecret(ref input, new SecretAttributes { Value = attributeValue }, new SecretProtectedValue { ProtValue = protectedValue }, client);

    private Guid AddSecret<TAttribute, TProtected>(
        ref ValidatedVaultDataSnapshot input,
        TAttribute attributeValue,
        TProtected protectedValue,
        ClientData client
    )
        where TAttribute : IBinarySerializable<TAttribute>, IJsonSerializable<TAttribute>
        where TProtected : IBinarySerializable<TProtected>
        => AddSecret(ref input, VaultIdentifier.Create<TAttribute, TProtected>("First Vault"), attributeValue, protectedValue, client);

    private Guid AddSecret<TAttribute, TProtected>(ref ValidatedVaultDataSnapshot input, VaultIdentifier id, TAttribute attributeValue, TProtected protectedValue, ClientData client)
        where TAttribute : IBinarySerializable<TAttribute>, IJsonSerializable<TAttribute>
        where TProtected : IBinarySerializable<TProtected>
    {
        LiveVaultData live = LiveVaultData.FromSnapshot(input);
        OpenVaultReader<TAttribute,TProtected> store = live.GetStoreOrDefault<TAttribute, TProtected>(id.Name);
        var secretId = store.GetWriter(s_transformer).Add(attributeValue, protectedValue);
        live.UpdateVault(store.ToSnapshot());
        input = live.GetSnapshot(new RefSigner(s_algorithm, client.PrivateInfo));
        return secretId;
    }

    private (string attr, string prot) GetSecretValues(ValidatedVaultDataSnapshot snapshot, Guid secretId)
        => GetSecretValues(snapshot, VaultIdentifier.Create<SecretAttributes, SecretProtectedValue>("First Vault"), secretId);

    private (string attr, string prot) GetSecretValues(ValidatedVaultDataSnapshot snapshot, VaultIdentifier vaultId, Guid secretId)
    {
        UnsealedSecret<SecretAttributes, SecretProtectedValue> secret = s_transformer.Unseal(GetSecret<SecretAttributes, SecretProtectedValue>(snapshot, vaultId, secretId));
        return (secret.Attributes.Value, secret.Protected.ProtValue);
    }

    private SealedSecret<TAttributes, TProtected> GetSecret<TAttributes, TProtected>(ValidatedVaultDataSnapshot snapshot, VaultIdentifier vaultId, Guid secretId)
        where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
        where TProtected : IBinarySerializable<TProtected>
    {
        return LiveVaultData.FromSnapshot(snapshot).GetStoreOrDefault<TAttributes, TProtected>(vaultId.Name).Get(secretId);
    }

    private ValidatedVaultDataSnapshot RemoveSecret(ValidatedVaultDataSnapshot input, VaultIdentifier vaultId, Guid secretId, ClientData client)
    {
        LiveVaultData live = LiveVaultData.FromSnapshot(input);
        live.RemoveSecret(vaultId, secretId);
        return live.GetSnapshot(new RefSigner(s_algorithm, client.PrivateInfo));
    }

    public ValidatedVaultDataSnapshot BuildBasicVault()
    {
        UnvalidatedVaultDataSnapshot snapshot = new(
            [
                s_self.Entry,
                s_trusted.Entry,
            ],
            [s_blocked.Blocked],
            [
                s_algorithm.Sign(
                    new ClientModificationRecord(ClientAction.Added, s_self.Id, default, default, s_self.Id),
                    s_self.PrivateInfo
                ),
                s_algorithm.Sign(
                    new ClientModificationRecord(ClientAction.Added, s_trusted.Id, default, default, s_self.Id),
                    s_self.PrivateInfo
                ),
                s_algorithm.Sign(
                    new ClientModificationRecord(ClientAction.Added, s_blocked.Id, default, default, s_trusted.Id),
                    s_trusted.PrivateInfo
                ),
                s_algorithm.Sign(
                    new ClientModificationRecord(ClientAction.Blocked, s_blocked.Id, default, default, s_self.Id),
                    s_self.PrivateInfo
                ),
            ],
            [
                new UntypedVaultSnapshot(
                    VaultIdentifier.Create<SecretAttributes, SecretProtectedValue>("First Vault"),
                    [
                        s_transformer.Seal(
                            UnsealedSecret.Create(
                                new SecretAttributes { Value = "Value 1" },
                                new SecretProtectedValue { ProtValue = "Protected 1" }
                            )
                        ),
                        s_transformer.Seal(
                            UnsealedSecret.Create(
                                new SecretAttributes { Value = "Value 2" },
                                new SecretProtectedValue { ProtValue = "Protected 2" }
                            )
                        ),
                    ],
                    []
                ),
                new UntypedVaultSnapshot(
                    VaultIdentifier.Create<OtherSecretAttributes, SecretProtectedValue>("Other Vault"),
                    [
                        s_transformer.Seal(
                            UnsealedSecret.Create(
                                new OtherSecretAttributes { Value = "Value 1" },
                                new SecretProtectedValue { ProtValue = "Protected 1" }
                            )
                        ),
                        s_transformer.Seal(
                            UnsealedSecret.Create(
                                new OtherSecretAttributes { Value = "Value 2" },
                                new SecretProtectedValue { ProtValue = "Protected 2" }
                            )
                        ),
                    ],
                    [
                        new RemovedSecretRecord(Guid.Parse("66666666-6666-6666-6666-666666666666"), 2, new byte[]{1,2,3,4}),
                        new RemovedSecretRecord(Guid.Parse("77777777-7777-7777-7777-777777777777"), 3, new byte[]{5,6,7,8}),
                    ]
                )
            ],
            6
        );
        
        return ValidatedVaultDataSnapshot.Validate(
            s_algorithm.Sign(
                snapshot,
                s_self.PrivateInfo
            ),
            s_self.PublicInfo.SigningKey.Span,
            s_algorithm
        );
    }

    [ProtoContract]
    public class OtherSecretAttributes : FullSerializable<OtherSecretAttributes>
    {
        [ProtoMember(1)]
        public string Value { get; set; }
    }
}