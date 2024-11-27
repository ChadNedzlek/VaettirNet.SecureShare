using System.IO;
using System.Threading.Tasks;
using FluentAssertions;
using NUnit.Framework;

namespace VaettirNet.TreeFormat.Tests;

public class TreeTests
{
    [Test]
    public async Task RoundTripTree()
    {
        VaultNodeBuilder builder = new();
        builder.AddNodeType<TestNodeValue>();
        var root = new VaultNode<TestNodeValue>(null, new TestNodeValue { Member = 5 }, new byte[] { 1, 2, 3 });
        var left1 = new VaultNode<TestNodeValue>(root, new TestNodeValue { Member = -7 }, new byte[] { 2, 3, 4 });
        var left2 = new VaultNode<TestNodeValue>(left1, new TestNodeValue { Member = -70 }, new byte[] { 3, 4, 5 });
        var rl = new VaultNode<TestNodeValue>(left1, new TestNodeValue { Member = -30 }, new byte[] { 4, 5, 6 });
        var another = new VaultNode<TestNodeValue>(root, new TestNodeValue { Member = 7 }, new byte[] { 5, 6, 7 });
        MemoryStream s = new();
        await builder.WriteTreeAsync(root, s);
        s.Flush();
        s.Position = 0;
        VaultNode tree = await builder.ReadTreeAsync(s);
        tree.Should().BeEquivalentTo(root);
    }
}