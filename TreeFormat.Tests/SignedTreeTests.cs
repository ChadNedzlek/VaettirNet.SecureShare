using System;
using System.Collections.Generic;
using System.Linq;
using FluentAssertions;
using NUnit.Framework;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Crypto;

namespace VaettirNet.TreeFormat.Tests;

public class SignedTreeTests
{
    [Test]
    public void BasicTest()
    {
        SignedTree tree = BuildTree(out VaultCryptographyAlgorithm alg, out PublicKeyInfo pub1);
    }
    
    [Test]
    public void IteratorTest()
    {
        SignedTree tree = BuildTree(out VaultCryptographyAlgorithm alg, out PublicKeyInfo pub1);
        var node = GetNode(tree, 22);
        var array = tree.GetBranchIteratorFromNodeToRoot(node).ToArray();
        array.Should().HaveCount(4);
        array[0].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(22);
        array[1].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(21);
        array[2].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(20);
        array[3].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(1);
    }
    
    [Test]
    public void ConflictLeftOnlyTest()
    {
        SignedTree tree = BuildTree(out VaultCryptographyAlgorithm alg, out PublicKeyInfo pub1);
        var node = GetNode(tree, 22);
        var resolution = tree.ResolveConflict(tree.Root, GetNode(tree, 12));
        var array = tree.GetBranchIteratorFromNodeToRoot(resolution).ToArray();
        array.Should().HaveCount(4);
        array[0].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(12);
        array[1].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(11);
        array[2].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(10);
        array[3].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(1);
    }
    
    [Test]
    public void ConflictRightOnlyTest()
    {
        SignedTree tree = BuildTree(out VaultCryptographyAlgorithm alg, out PublicKeyInfo pub1);
        var node = GetNode(tree, 22);
        var resolution = tree.ResolveConflict(tree.Root, GetNode(tree, 22));
        var array = tree.GetBranchIteratorFromNodeToRoot(resolution).ToArray();
        array.Should().HaveCount(4);
        array[0].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(22);
        array[1].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(21);
        array[2].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(20);
        array[3].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(1);
    }
    
    [Test]
    public void ConflictLeftThenRightTest()
    {
        SignedTree tree = BuildTree(out VaultCryptographyAlgorithm alg, out PublicKeyInfo pub1);
        var node = GetNode(tree, 22);
        var resolution = tree.ResolveConflict(tree.Root, GetNode(tree, 12), GetNode(tree, 22));
        var array = tree.GetBranchIteratorFromNodeToRoot(resolution).ToArray();
        array.Should().HaveCount(7);
        array[0].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(22);
        array[1].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(21);
        array[2].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(20);
        array[3].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(12);
        array[4].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(11);
        array[5].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(10);
        array[6].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(1);
    }
    
    [Test]
    public void ConflictRightThenLeftTest()
    {
        SignedTree tree = BuildTree(out VaultCryptographyAlgorithm alg, out PublicKeyInfo pub1);
        var node = GetNode(tree, 22);
        var resolution = tree.ResolveConflict(tree.Root, GetNode(tree, 22), GetNode(tree, 12));
        var array = tree.GetBranchIteratorFromNodeToRoot(resolution).ToArray();
        array.Should().HaveCount(7);
        array[0].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(12);
        array[1].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(11);
        array[2].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(10);
        array[3].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(22);
        array[4].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(21);
        array[5].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(20);
        array[6].Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(1);
    }

    private static SignedTree BuildTree(out VaultCryptographyAlgorithm alg, out PublicKeyInfo pub1)
    {
        alg = new();
        alg.CreateKeys(Guid.NewGuid(), out var priv1, out pub1);
        SignedTree tree = new(new AddTrustValue(pub1), new ValueNode(1), new TestTrustResolver());
        tree.Root.Value.Should().BeOfType<ValueNode>().Which.Value.Should().Be(1);
        var node10 = tree.AddValueNode(new ValueNode(10), tree.Root);
        var node11 = tree.AddValueNode(new ValueNode(11), node10);
        var node12 = tree.AddValueNode(new ValueNode(12), node11);
        var node20 = tree.AddValueNode(new ValueNode(20), tree.Root);
        var node21 = tree.AddValueNode(new ValueNode(21), node20);
        var node22 = tree.AddValueNode(new ValueNode(22), node21);
        return tree;
    }

    private DagNode GetNode(SignedTree tree, int value)
    {
        return Search(tree.Root);
        
        DagNode Search(DagNode node)
        {
            if (node.Value is ValueNode { Value: var v } && v == value) return node;
            return node.Children.Select(Search).FirstOrDefault(x => x is not null);
        }
    }

    public class TestTrustResolver : ISignedTreeTrustResolver
    {
        public TrustedPublicKeys UpdateTrust(TrustedPublicKeys parentTrust, SignedTree.TrustNodeValue nodeValue)
        {
            return nodeValue switch
            {
                AddTrustValue add => parentTrust.With(add.PublicKeyInfo),
                RemoveTrustValue remove => parentTrust.Without(remove.Id),
                _ => throw new ArgumentOutOfRangeException(nameof(nodeValue), nodeValue, "Unepxected value"),
            };
        }
    }

    [PackedBinarySerializable]
    public class AddTrustValue : SignedTree.TrustNodeValue
    {
        public AddTrustValue(PublicKeyInfo publicKeyInfo)
        {
            PublicKeyInfo = publicKeyInfo;
        }

        public override bool TryGetDataToSign(Span<byte> destination, out int cb)
        {
            cb = 0;
            return true;
        }

        public PublicKeyInfo PublicKeyInfo { get; }
        public override string ToString() => $"Add {PublicKeyInfo.Id}";
    }
    [PackedBinarySerializable]
    public class RemoveTrustValue : SignedTree.TrustNodeValue
    {
        public RemoveTrustValue(Guid id)
        {
            Id = id;
        }

        public override bool TryGetDataToSign(Span<byte> destination, out int cb)
        {
            cb = 0;
            return true;
        }

        public Guid Id { get; }
        public override string ToString() => $"Remove {Id}";
    }

    [PackedBinarySerializable]
    public class ValueNode : SignedTree.ValueNodeValue
    {
        public ValueNode(int value)
        {
            Value = value;
        }

        public override bool TryGetDataToSign(Span<byte> destination, out int cb)
        {
            cb = 0;
            return true;
        }
        
        public int Value { get; }

        public override string ToString() => Value.ToString();
    }
}