using FluentAssertions;
using VaettirNet.SecureShare;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Vaults;

// ReSharper disable PossibleNullReferenceException

namespace SecureShare.Tests;

public class VaultTest
{
    [Test]
    public void SerializeSnapshot()
    {
        var firstClient =   Guid.Parse("11111111-1111-1111-1111-111111111111");
        var blockedClient = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var secret =        Guid.Parse("33333333-3333-3333-3333-333333333333");
        var blockedSecret = Guid.Parse("44444444-4444-4444-4444-444444444444");
        SecretTransformer transformer = SecretTransformer.CreateRandom();
        VaultDataSnapshot snapshot = new(
            [
                new VaultClientEntry
                (
                     firstClient,
                    "First Client",
                     new byte[] { 1, 2, 3 },
                     new byte[] { 4, 5, 6 },
                     new byte[] { 7, 8, 9 },
                     firstClient
                ),
            ],
            [new BlockedVaultClientEntry { ClientId = blockedClient, Description = "Blocked Client", PublicKey = new byte[] { 10, 11, 12 } }],
            [
                Signed.Create(
                    new ClientModificationRecord(
                        ClientAction.Added,
                        firstClient,
                        new byte[] { 4, 5, 6 },
                        new byte[] { 1, 2, 3 },
                        firstClient
                    ),
                    firstClient,
                    new byte[] { 13, 14, 15 }
                )
            ],
            [
                new UntypedVaultSnapshot(
                    VaultIdentifier.Create<SecretAttributes, SecretProtectedValue>(),
                    [
                        transformer.Seal(
                            new UnsealedSecretValue<SecretAttributes, SecretProtectedValue>(
                                secret,
                                new() { Value = "Attribute Value" },
                                new() { ProtValue = "Protected Value" }
                            )
                        )
                    ],
                    [
                        Signed.Create(
                            new RemovedSecretRecord(blockedSecret, 1, new byte[] { 20, 21, 22 }),
                            firstClient,
                            new byte[] { 23, 24, 25 }
                        )
                    ]
                )
            ]
        );

        VaultSnapshotSerializer serializer = VaultSnapshotSerializer.CreateBuilder()
            .WithSecret<SecretAttributes, SecretProtectedValue>()
            .Build();
        using MemoryStream stream = new();
        serializer.Serialize(stream, new Signed<VaultDataSnapshot>(snapshot, firstClient, new byte[] { 30, 31, 32 }));
        stream.Flush();
        stream.Position = 0;
        var roundTripped = serializer.Deserialize(stream);
        roundTripped.Should().BeEquivalentTo(snapshot, o =>
            {
                o.ComparingByMembers<PublicClientInfo>();
                o.Using<ReadOnlyMemory<byte>, MemoryComparer<byte>>();
                return o;
            }
        );
    }

    private class MemoryComparer<T> : IEqualityComparer<ReadOnlyMemory<T>>
    {
        private readonly IEqualityComparer<T> _itemComparer;

        public MemoryComparer() : this(EqualityComparer<T>.Default)
        {
        }

        public MemoryComparer(IEqualityComparer<T> itemComparer)
        {
            _itemComparer = itemComparer;
        }

        public bool Equals(ReadOnlyMemory<T> x, ReadOnlyMemory<T> y)
        {
            if (x.Length != y.Length)
            {
                return false;
            }

            ReadOnlySpan<T> a = x.Span, b = y.Span;

            for (int i = 0; i < x.Length; i++)
            {
                if (!_itemComparer.Equals(a[i], b[i]))
                {
                    return false;
                }
            }

            return true;
        }

        public int GetHashCode(ReadOnlyMemory<T> obj)
        {
            HashCode h = new();
            foreach(T i in obj.Span){
                h.Add(_itemComparer.GetHashCode(i));
            }
            return h.ToHashCode();
        }
    }
}