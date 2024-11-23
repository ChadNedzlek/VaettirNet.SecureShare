using FluentAssertions;
using FluentAssertions.Execution;
using FluentAssertions.Primitives;
using VaettirNet.PackedBinarySerialization.Attributes;
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
    private static ValidatedVaultDataSnapshot s_basicVault;

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

        s_basicVault = BuildBasicVault();
    }

    [Test]
    public void NoChangeConflict()
    {
        VaultConflictResult resolution = s_resolver.Resolve(s_basicVault, s_basicVault, s_basicVault);
        resolution.Items.Should().BeEmpty();
        s_resolver.TryAutoResolveConflicts(resolution, new RefSigner(s_algorithm, s_new.PrivateInfo), out ValidatedVaultDataSnapshot snapshot).Should().BeTrue();
        snapshot.TryGetSignerPublicInfo(out PublicClientInfo signerInfo).Should().BeTrue();
        signerInfo.ClientId.Should().Be(s_self.Id, because: "no conflict should not resign/modify vault");
    }
    
    [Test]
    public void LocalOnlyModification()
    {
        ValidatedVaultDataSnapshot modifiedVault = s_basicVault;
        Guid id = AddSecret(ref modifiedVault, "Added Secret", "Added Prot", s_self);
        VaultConflictResult resolution = s_resolver.Resolve(s_basicVault, s_basicVault, modifiedVault);
        resolution.Items.Should().BeEmpty();
        s_resolver.TryAutoResolveConflicts(resolution, new RefSigner(s_algorithm, s_new.PrivateInfo), out ValidatedVaultDataSnapshot snapshot).Should().BeTrue();
        snapshot.TryGetSignerPublicInfo(out PublicClientInfo signerInfo).Should().BeTrue();
        signerInfo.ClientId.Should().Be(s_self.Id, because: "no conflict should not resign/modify vault");
        (string attributeValue, string protectedValue) = GetSecretValues(snapshot, id);
        attributeValue.Should().Be("Added Secret");
        protectedValue.Should().Be("Added Prot");
    }
    
    [Test]
    public void RemoteOnlyModification()
    {
        ValidatedVaultDataSnapshot modifiedVault = BuildBasicVault();
        Guid id = AddSecret(ref modifiedVault, "Added Secret", "Added Prot", s_self);
        VaultConflictResult resolution = s_resolver.Resolve(s_basicVault, modifiedVault, s_basicVault);
        resolution.Items.Should().BeEmpty();
        s_resolver.TryAutoResolveConflicts(resolution, new RefSigner(s_algorithm, s_new.PrivateInfo), out ValidatedVaultDataSnapshot snapshot).Should().BeTrue();
        snapshot.TryGetSignerPublicInfo(out PublicClientInfo signerInfo).Should().BeTrue();
        signerInfo.ClientId.Should().Be(s_self.Id, because: "no conflict should not resign/modify vault");
        (string attributeValue, string protectedValue) = GetSecretValues(snapshot, id);
        attributeValue.Should().Be("Added Secret");
        protectedValue.Should().Be("Added Prot");
    }
    
    [Test]
    public void DualAddsAreMergedOnlyModification()
    {
        ValidatedVaultDataSnapshot modifiedLocalVault = BuildBasicVault();
        Guid localId = AddSecret(ref modifiedLocalVault, "Local Secret", "Local Prot", s_new);
        ValidatedVaultDataSnapshot modifiedRemoteVault = BuildBasicVault();
        Guid remoteId = AddSecret(ref modifiedRemoteVault, "Remote Secret", "Remote Prot", s_trusted);
        VaultConflictResult conflict = s_resolver.Resolve(s_basicVault, modifiedRemoteVault, modifiedLocalVault);
        conflict.Items.Should().NotBeEmpty();
        s_resolver.TryAutoResolveConflicts(conflict, new RefSigner(s_algorithm, s_new.PrivateInfo), out ValidatedVaultDataSnapshot snapshot).Should().BeTrue();
        snapshot.TryGetSignerPublicInfo(out PublicClientInfo signerInfo).Should().BeTrue();
        signerInfo.ClientId.Should().Be(s_self.Id, because: "no conflict should resign/modify vault");
        (string remoteAttribute, string remoteProtected) = GetSecretValues(snapshot, remoteId);
        remoteAttribute.Should().Be("Remote Secret");
        remoteProtected.Should().Be("Remote Prot");
        (string localAttribute, string localProtected) = GetSecretValues(snapshot, localId);
        localAttribute.Should().Be("Local Secret");
        localProtected.Should().Be("Local Prot");
    }
    
    [Test]
    public void AutoResolveResolvesAllTrivial()
    {
        ValidatedVaultDataSnapshot modifiedLocalVault = BuildBasicVault();
        Guid localId = AddSecret(ref modifiedLocalVault, "Local Secret", "Local Prot", s_new);
        ValidatedVaultDataSnapshot modifiedRemoteVault = BuildBasicVault();
        Guid remoteId = AddSecret(ref modifiedRemoteVault, "Remote Secret", "Remote Prot", s_trusted);
        VaultConflictResult conflict = s_resolver.Resolve(s_basicVault, modifiedRemoteVault, modifiedLocalVault);
        conflict.Items.Should().NotBeEmpty();
        PartialVaultConflictResolution resolver = conflict.GetResolver();
        resolver.TryGetNextUnresolved(out _).Should().BeTrue();
        resolver.Apply(s_algorithm, s_self.PrivateInfo).TryGetValue(out _).Should().BeFalse();
        resolver = resolver.WithAutoResolutions();
        resolver.TryGetNextUnresolved(out _).Should().BeFalse();
        resolver.Apply(s_algorithm, s_self.PrivateInfo).TryGetValue(out var resolvedVault).Should().BeTrue();
        (string remoteAttribute, string remoteProtected) = GetSecretValues(resolvedVault, remoteId);
        remoteAttribute.Should().Be("Remote Secret");
        remoteProtected.Should().Be("Remote Prot");
        (string localAttribute, string localProtected) = GetSecretValues(resolvedVault, localId);
        localAttribute.Should().Be("Local Secret");
        localProtected.Should().Be("Local Prot");
    }

    [Test]
    public void ConflictingModificationsReportsConflict()
    {
        ValidatedVaultDataSnapshot original = BuildBasicVault();
        Guid id = original.Vaults.SelectMany(v => v.Secrets)
            .OfType<SealedSecret<SecretAttributes, SecretProtectedValue>>()
            .First(s => s.Attributes.Value == "Value 1")
            .Id;
        
        ValidatedVaultDataSnapshot modifiedRemoteVault = original;
        ValidatedVaultDataSnapshot modifiedLocalVault = original;
        UpdateSecret(ref modifiedRemoteVault, id, "Remote Secret", "Remote Prot", s_trusted);
        UpdateSecret(ref modifiedLocalVault, id, "Local Secret", "Local Prot", s_self);
        
        VaultConflictResult conflict = s_resolver.Resolve(original, modifiedRemoteVault, modifiedLocalVault);
        SecretConflictItem conflictItem = conflict.Items.Should().ContainSingle().Which.Should().BeOfType<SecretConflictItem>().Subject;
        s_resolver.TryAutoResolveConflicts(conflict, new RefSigner(s_algorithm, s_new.PrivateInfo), out _).Should().BeFalse();
        var baseSecret = conflictItem.BaseEntry.Should().BeOfType<SealedSecret<SecretAttributes, SecretProtectedValue>>().Subject;
        conflictItem.Local.Is<UntypedSealedSecret>(out var localUntyped).Should().BeTrue();
        var localSecret = localUntyped.Should()
            .BeOfType<SealedSecret<SecretAttributes, SecretProtectedValue>>()
            .Subject;
        conflictItem.Remote.Is<UntypedSealedSecret>(out var remoteUntyped).Should().BeTrue();
        var remoteSecret = remoteUntyped.Should()
            .BeOfType<SealedSecret<SecretAttributes, SecretProtectedValue>>()
            .Subject;
        baseSecret.Attributes.Value.Should().Be("Value 1");
        localSecret.Attributes.Value.Should().Be("Local Secret");
        remoteSecret.Attributes.Value.Should().Be("Remote Secret");
    }
    
    [Test]
    public void ConflictingModificationsDefaultResolveLocal()
    {
        ValidatedVaultDataSnapshot original = BuildBasicVault();
        Guid id = original.Vaults.SelectMany(v => v.Secrets)
            .OfType<SealedSecret<SecretAttributes, SecretProtectedValue>>()
            .First()
            .Id;
        
        ValidatedVaultDataSnapshot modifiedRemoteVault = original;
        ValidatedVaultDataSnapshot modifiedLocalVault = original;
        UpdateSecret(ref modifiedRemoteVault, id, "Remote Secret", "Remote Prot", s_trusted);
        UpdateSecret(ref modifiedLocalVault, id, "Local Secret", "Local Prot", s_self);
        
        VaultConflictResult conflict = s_resolver.Resolve(original, modifiedRemoteVault, modifiedLocalVault);
        var resolver = conflict.GetResolver();
        resolver.Apply(s_algorithm, s_self.PrivateInfo, VaultResolutionItem.AcceptLocal).TryGetValue(out var resolvedVault).Should().BeTrue();
        var (attribute, prot) = GetSecretValues(resolvedVault, id);
        attribute.Should().Be("Local Secret");
        prot.Should().Be("Local Prot");
    }
    
    [Test]
    public void ConflictingModificationsSpecificResolveLocal()
    {
        ValidatedVaultDataSnapshot original = BuildBasicVault();
        Guid id = original.Vaults.SelectMany(v => v.Secrets)
            .OfType<SealedSecret<SecretAttributes, SecretProtectedValue>>()
            .First()
            .Id;
        
        ValidatedVaultDataSnapshot modifiedRemoteVault = original;
        ValidatedVaultDataSnapshot modifiedLocalVault = original;
        UpdateSecret(ref modifiedRemoteVault, id, "Remote Secret", "Remote Prot", s_trusted);
        UpdateSecret(ref modifiedLocalVault, id, "Local Secret", "Local Prot", s_self);
        
        VaultConflictResult conflict = s_resolver.Resolve(original, modifiedRemoteVault, modifiedLocalVault);
        var resolver = conflict.GetResolver();
        resolver.TryGetNextUnresolved(out VaultConflictItem unresolved).Should().BeTrue();
        var localResolution = resolver.WithResolution(unresolved!, VaultResolutionItem.AcceptLocal);
        localResolution.TryGetNextUnresolved(out _).Should().BeFalse();
        localResolution.Apply(s_algorithm, s_self.PrivateInfo).TryGetValue(out var resolvedVault).Should().BeTrue();
        (string attribute, string prot) = GetSecretValues(resolvedVault, id);
        attribute.Should().Be("Local Secret");
        prot.Should().Be("Local Prot");
    }
    
    [Test]
    public void ConflictingModificationsDefaultResolveRemote()
    {
        ValidatedVaultDataSnapshot original = BuildBasicVault();
        Guid id = original.Vaults.SelectMany(v => v.Secrets)
            .OfType<SealedSecret<SecretAttributes, SecretProtectedValue>>()
            .First()
            .Id;
        
        ValidatedVaultDataSnapshot modifiedRemoteVault = original;
        ValidatedVaultDataSnapshot modifiedLocalVault = original;
        UpdateSecret(ref modifiedRemoteVault, id, "Remote Secret", "Remote Prot", s_trusted);
        UpdateSecret(ref modifiedLocalVault, id, "Local Secret", "Local Prot", s_self);
        
        VaultConflictResult conflict = s_resolver.Resolve(original, modifiedRemoteVault, modifiedLocalVault);
        s_resolver.TryAutoResolveConflicts(conflict, new RefSigner(s_algorithm, s_new.PrivateInfo), out _).Should().BeFalse();
        var resolver = conflict.GetResolver();
        resolver.Apply(s_algorithm, s_self.PrivateInfo, VaultResolutionItem.AcceptRemote).TryGetValue(out var resolvedVault).Should().BeTrue();
        var (attribute, prot) = GetSecretValues(resolvedVault, id);
        attribute.Should().Be("Remote Secret");
        prot.Should().Be("Remote Prot");
    }
    
    [Test]
    public void ConflictingModificationsSpecificResolveRemote()
    {
        ValidatedVaultDataSnapshot original = BuildBasicVault();
        Guid id = original.Vaults.SelectMany(v => v.Secrets)
            .OfType<SealedSecret<SecretAttributes, SecretProtectedValue>>()
            .First()
            .Id;
        
        ValidatedVaultDataSnapshot modifiedRemoteVault = original;
        ValidatedVaultDataSnapshot modifiedLocalVault = original;
        UpdateSecret(ref modifiedRemoteVault, id, "Remote Secret", "Remote Prot", s_trusted);
        UpdateSecret(ref modifiedLocalVault, id, "Local Secret", "Local Prot", s_self);
        
        VaultConflictResult conflict = s_resolver.Resolve(original, modifiedRemoteVault, modifiedLocalVault);
        var resolver = conflict.GetResolver();
        resolver.TryGetNextUnresolved(out VaultConflictItem unresolved).Should().BeTrue();
        
        var remoteResolution = resolver.WithResolution(unresolved!, VaultResolutionItem.AcceptRemote);
        remoteResolution.TryGetNextUnresolved(out _).Should().BeFalse();
        remoteResolution.Apply(s_algorithm, s_self.PrivateInfo).TryGetValue(out var resolvedVault).Should().BeTrue();
        var (attribute, prot) = GetSecretValues(resolvedVault, id);
        attribute.Should().Be("Remote Secret");
        prot.Should().Be("Remote Prot");
    }

    [Test]
    public void DifferentResolutionsResolvedTogether()
    {
        ValidatedVaultDataSnapshot original = BuildBasicVault();
        
        Guid id1 = original.Vaults.SelectMany(v => v.Secrets)
            .OfType<SealedSecret<SecretAttributes, SecretProtectedValue>>()
            .First(s => s.Attributes.Value == "Value 1")
            .Id;

        Guid id2 = original.Vaults.SelectMany(v => v.Secrets)
            .OfType<SealedSecret<SecretAttributes, SecretProtectedValue>>()
            .First(s => s.Attributes.Value == "Value 2")
            .Id;

        ValidatedVaultDataSnapshot modifiedRemoteVault = original;
        ValidatedVaultDataSnapshot modifiedLocalVault = original;
        UpdateSecret(ref modifiedRemoteVault, id1, "Remote Secret 1", "Remote Prot 1", s_trusted);
        UpdateSecret(ref modifiedLocalVault, id1, "Local Secret 1", "Local Prot 1", s_self);
        UpdateSecret(ref modifiedRemoteVault, id2, "Remote Secret 2", "Remote Prot 2", s_trusted);
        UpdateSecret(ref modifiedLocalVault, id2, "Local Secret 2", "Local Prot 2", s_self);
        
        VaultConflictResult conflict = s_resolver.Resolve(original, modifiedRemoteVault, modifiedLocalVault);
        PartialVaultConflictResolution resolver = conflict.GetResolver();
        int iterationCount = 0;
        while (resolver.TryGetNextUnresolved(out var unresolved))
        {
            (iterationCount++).Should().BeLessThanOrEqualTo(2, because: "should only have two conflicts that are resolved");
            SecretConflictItem secretConflict = unresolved.Should().BeOfType<SecretConflictItem>().Subject;
            secretConflict.BaseEntry.Id.Should().BeOneOf(id1, id2);
            if (secretConflict.BaseEntry.Id == id1)
            {
                resolver = resolver.WithResolution(unresolved, VaultResolutionItem.AcceptLocal);
            }
            else if (secretConflict.BaseEntry.Id == id2)
            {
                resolver = resolver.WithResolution(unresolved, VaultResolutionItem.AcceptRemote);
            }
        }

        resolver.Apply(s_algorithm, s_self.PrivateInfo).TryGetValue(out var resolvedVault).Should().BeTrue();
        var (attribute, prot) = GetSecretValues(resolvedVault, id1);
        attribute.Should().Be("Local Secret 1");
        prot.Should().Be("Local Prot 1");
        (attribute, prot) = GetSecretValues(resolvedVault, id2);
        attribute.Should().Be("Remote Secret 2");
        prot.Should().Be("Remote Prot 2");
        
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
        Guid secretId = store.GetWriter(s_transformer).Add(attributeValue, protectedValue);
        live.UpdateVault(store.ToSnapshot());
        input = live.GetSnapshot(new RefSigner(s_algorithm, client.PrivateInfo));
        return secretId;
    }

    private void UpdateSecret(
        ref ValidatedVaultDataSnapshot input,
        Guid id,
        string attributeValue,
        string protectedValue,
        ClientData client
    ) => UpdateSecret(ref input, id, new SecretAttributes { Value = attributeValue }, new SecretProtectedValue { ProtValue = protectedValue }, client);

    private void UpdateSecret<TAttribute, TProtected>(
        ref ValidatedVaultDataSnapshot input,
        Guid id,
        TAttribute attributeValue,
        TProtected protectedValue,
        ClientData client
    )
        where TAttribute : IBinarySerializable<TAttribute>, IJsonSerializable<TAttribute>
        where TProtected : IBinarySerializable<TProtected>
        => UpdateSecret(ref input, VaultIdentifier.Create<TAttribute, TProtected>("First Vault"), id, attributeValue, protectedValue, client);

    private void UpdateSecret<TAttribute, TProtected>(
        ref ValidatedVaultDataSnapshot input,
        VaultIdentifier vaultId,
        Guid secretId,
        TAttribute attributeValue,
        TProtected protectedValue,
        ClientData client
    )
        where TAttribute : IBinarySerializable<TAttribute>, IJsonSerializable<TAttribute>
        where TProtected : IBinarySerializable<TProtected>
    {
        LiveVaultData live = LiveVaultData.FromSnapshot(input);
        OpenVaultReader<TAttribute,TProtected> store = live.GetStoreOrDefault<TAttribute, TProtected>(vaultId.Name);
        store.GetWriter(s_transformer).Update(secretId, attributeValue, protectedValue);
        live.UpdateVault(store.ToSnapshot());
        input = live.GetSnapshot(new RefSigner(s_algorithm, client.PrivateInfo));
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

    public static ValidatedVaultDataSnapshot BuildBasicVault()
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

    [PackedBinarySerializable]
    public class OtherSecretAttributes : FullSerializable<OtherSecretAttributes>
    {
        [PackedBinaryMember(1)]
        public string Value { get; set; }
    }
}

public static class AssertionExtensions
{
    public static void BeOneOf(this GuidAssertions assertions, Guid[] expectations, string because, params object[] args) {
        Execute.Assertion
            .ForCondition(expectations.Any(x => x == assertions.Subject))
            .BecauseOf(because, args)
            .FailWith("Expected {context:string} to be any of {0}{reason}", expectations);
    }
    public static void BeOneOf(this GuidAssertions assertions, params Guid[] expectations) {
        Execute.Assertion
            .ForCondition(expectations.Any(x => x == assertions.Subject))
            .FailWith("Expected {context:string} to be any of {0}{reason}", expectations);
    }
}