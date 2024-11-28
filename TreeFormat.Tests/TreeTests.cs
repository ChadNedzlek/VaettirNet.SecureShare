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
        SignedDirectedAcyclicGraph.Node root = directedAcyclicGraph.Root;
        SignedDirectedAcyclicGraph.Node left1 = directedAcyclicGraph.CreateNode(CreateRecord(-7), keys, root);
        SignedDirectedAcyclicGraph.Node left2 = directedAcyclicGraph.CreateNode(CreateRecord(-70), keys, left1);
        SignedDirectedAcyclicGraph.Node rl = directedAcyclicGraph.CreateNode(CreateRecord(-30), keys, left1);
        SignedDirectedAcyclicGraph.Node another = directedAcyclicGraph.CreateNode(CreateRecord(7), keys, root);
        MemoryStream s = new();
        await builder.WriteTreeAsync(directedAcyclicGraph, s, privateInfo, alg);
        s.Flush();
        s.Position = 0;
        SignedDirectedAcyclicGraph roundTripped = await builder.ReadTreeAsync(s, (_, _) => keys, alg);
        roundTripped.Root.Should()
            .BeEquivalentTo(
                directedAcyclicGraph.Root,
                o => o.IgnoringCyclicReferences()
            );

        TestNodeValue CreateRecord(int value) => new() { Member = value };
    }
    
    [Test]
    public async Task NodeOrderFixed()
    {
        VaultNodeBuilder builder = new();
        builder.AddNodeType<TestNodeValue>();
        VaultCryptographyAlgorithm alg = new();
        alg.CreateKeys(Guid.NewGuid(), out PrivateKeyInfo privateInfo, out PublicKeyInfo publicInfo);
        TrustedPublicKeys keys = new TrustedPublicKeys().With(publicInfo);
        SignedDirectedAcyclicGraph directedAcyclicGraph = MakeGraph(keys);
        MemoryStream s = new();
        await builder.WriteTreeAsync(directedAcyclicGraph, s, privateInfo, alg);
        byte[] originalBytes = s.ToArray();
        s.Flush();
        s.Position = 0;
        SignedDirectedAcyclicGraph roundTripped = await builder.ReadTreeAsync(s, (_, _) => keys, alg);
        s.Flush();
        s.Position = 0;
        await builder.WriteTreeAsync(roundTripped, s, privateInfo, alg);
        byte[] rewrittenBytes = s.ToArray();
        
        roundTripped.Root.Should()
            .BeEquivalentTo(
                directedAcyclicGraph.Root,
                o => o.IgnoringCyclicReferences()
            );
        rewrittenBytes.Should().BeEquivalentTo(originalBytes);
    }

    private static SignedDirectedAcyclicGraph MakeGraph(TrustedPublicKeys keys)
    {
        SignedDirectedAcyclicGraph directedAcyclicGraph = new(CreateRecord(5), keys);
        SignedDirectedAcyclicGraph.Node root = directedAcyclicGraph.Root;
        SignedDirectedAcyclicGraph.Node left1 = directedAcyclicGraph.CreateNode(CreateRecord(-7), keys, root);
        SignedDirectedAcyclicGraph.Node left2 = directedAcyclicGraph.CreateNode(CreateRecord(-70), keys, left1);
        SignedDirectedAcyclicGraph.Node rl = directedAcyclicGraph.CreateNode(CreateRecord(-30), keys, left1);
        SignedDirectedAcyclicGraph.Node another = directedAcyclicGraph.CreateNode(CreateRecord(7), keys, root);
        return directedAcyclicGraph;
        TestNodeValue CreateRecord(int value) => new() { Member = value };
    }
}