using System;
using System.IO;
using System.Threading.Tasks;
using FluentAssertions;
using NUnit.Framework;
using VaettirNet.SecureShare.Crypto;

namespace VaettirNet.TreeFormat.Tests;

public class TreeTests
{
    [Test]
    public async Task RoundTripTree()
    {
        VaultNodeBuilder builder = new();
        builder.AddNodeType<TestNodeValue>();
        VaultCryptographyAlgorithm alg = new();
        alg.CreateKeys(Guid.NewGuid(), out PrivateKeyInfo privateInfo, out PublicKeyInfo publicInfo);
        TrustedPublicKeys keys = new TrustedPublicKeys().With(publicInfo);
        SignedTree tree = new(CreateRecord(5), keys);
        // var root = tree.Root;
        // var left1 = tree.CreateNode(CreateRecord(-7), keys, root);
        // var left2 = tree.CreateNode(CreateRecord(-70), keys, left1);
        // var rl = tree.CreateNode(CreateRecord(-30), keys, left1);
        // var another = tree.CreateNode(CreateRecord(7), keys, root);
        MemoryStream s = new();
        await builder.WriteTreeAsync(tree, s);
        s.Flush();
        s.Position = 0;
        var roundTripped = await builder.ReadTreeAsync(s, (_, _) => keys, alg);
        roundTripped.Root.Should().BeEquivalentTo(tree.Root);

        Validated<NodeRecord> CreateRecord(int value)
        {
            return alg.Sign(new NodeRecord(new TestNodeValue { Member = value }), privateInfo);
        }
    }
}