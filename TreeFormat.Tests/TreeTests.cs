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
        SignedDirectedAcyclicGraph directedAcyclicGraph = new(CreateRecord(5), keys);
        var root = directedAcyclicGraph.Root;
        var left1 = directedAcyclicGraph.CreateNode(CreateRecord(-7), keys);
        var left2 = directedAcyclicGraph.CreateNode(CreateRecord(-70), keys);
        var rl = directedAcyclicGraph.CreateNode(CreateRecord(-30), keys);
        var another = directedAcyclicGraph.CreateNode(CreateRecord(7), keys);
        MemoryStream s = new();
        await builder.WriteTreeAsync(directedAcyclicGraph, s, privateInfo, alg);
        s.Flush();
        s.Position = 0;
        var roundTripped = await builder.ReadTreeAsync(s, (_, _) => keys, alg);
        roundTripped.Root.Should().BeEquivalentTo(directedAcyclicGraph.Root);

        Validated<NodeRecord> CreateRecord(int value)
        {
            return alg.Sign(new NodeRecord(new TestNodeValue { Member = value }), privateInfo);
        }
    }
    
    [Test]
    public async Task NodeOrderFixed()
    {
        VaultNodeBuilder builder = new();
        builder.AddNodeType<TestNodeValue>();
        VaultCryptographyAlgorithm alg = new();
        alg.CreateKeys(Guid.NewGuid(), out PrivateKeyInfo privateInfo, out PublicKeyInfo publicInfo);
        TrustedPublicKeys keys = new TrustedPublicKeys().With(publicInfo);
        SignedDirectedAcyclicGraph directedAcyclicGraph = new(CreateRecord(5), keys);
        var root = directedAcyclicGraph.Root;
        var left1 = directedAcyclicGraph.CreateNode(CreateRecord(-7), keys);
        var left2 = directedAcyclicGraph.CreateNode(CreateRecord(-70), keys);
        var rl = directedAcyclicGraph.CreateNode(CreateRecord(-30), keys);
        var another = directedAcyclicGraph.CreateNode(CreateRecord(7), keys);
        MemoryStream s = new();
        await builder.WriteTreeAsync(directedAcyclicGraph, s, privateInfo, alg);
        s.Flush();
        s.Position = 0;
        var originalBytes = s.ToArray();
        var roundTripped = await builder.ReadTreeAsync(s, (_, _) => keys, alg);
        s.Flush();
        s.Position = 0;
        await builder.WriteTreeAsync(roundTripped, s, privateInfo, alg);
        var rewrittenBytes = s.ToArray();
        rewrittenBytes.Should().BeEquivalentTo(originalBytes);

        Validated<NodeRecord> CreateRecord(int value)
        {
            return alg.Sign(new NodeRecord(new TestNodeValue { Member = value }), privateInfo);
        }
    }
}