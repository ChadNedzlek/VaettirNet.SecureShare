using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using VaettirNet.PackedBinarySerialization;
using VaettirNet.SecureShare.Crypto;

namespace VaettirNet.TreeFormat;

public class VaultNodeBuilder
{
    private static bool s_initialized;
    private static readonly Lock s_lock = new();
    private readonly List<Type> _valueTypes = new();

    private void Initialize()
    {
        if (s_initialized)
            return;
        lock (s_lock)
        {
            if (s_initialized)
                return;

            s_initialized = true;
        }
    }

    public SignedTree BuildTree(
        IEnumerable<Signed<NodeRecord>> records,
        Func<IReadOnlyList<SignedTree.Node>, NodeValue, TrustedPublicKeys> establishTrust,
        VaultCryptographyAlgorithm alg
    )
    {
        Dictionary<SignedTree.NodeId, SignedTree.Node> nodes = new();
        SignedTree tree = null;
        foreach (Signed<NodeRecord> signed in records)
        {
            NodeRecord record = signed.DangerousGetPayload();
            List<SignedTree.Node> parents = record.ParentSignatures.Select(sig => nodes[new (sig)]).ToList();

            TrustedPublicKeys keys = establishTrust(parents, record.Value);
            SignedTree.Node newNode;
            if (tree is null)
            {
                tree = new SignedTree(signed.Validate(keys.Get(signed.Signer).SigningKey.Span, alg), keys);
                newNode = tree.Root;
            }
            else
            {
                if (parents.Count == 0) throw new ArgumentException("Multiple root nodes detected", nameof(nodes));
                
                newNode = tree.CreateNode(signed.Validate(keys.Get(signed.Signer).SigningKey.Span, alg), keys, parents);
            }
            nodes.Add(newNode.Id, newNode);
        }

        if (tree is null) throw new ArgumentException("No root node detected", nameof(nodes));

        return tree;
    }

    public VaultNodeBuilder AddNodeType<T>()
    {
        _valueTypes.Add(typeof(T));
        return this;
    }

    public Task<SignedTree> ReadTreeAsync(
        Stream source,
        Func<IReadOnlyList<SignedTree.Node>, NodeValue, TrustedPublicKeys> establishTrust,
        VaultCryptographyAlgorithm alg
    )
    {
        PackedBinarySerializer s = GetSerializer();
        Signed<NodeRecord>[] records = s.Deserialize<Signed<NodeRecord>[]>(source, new PackedBinarySerializationOptions(ImplicitRepeat: true));
        return Task.FromResult(BuildTree(records, establishTrust, alg));
    }

    public Task WriteTreeAsync(SignedTree tree, Stream destination)
    {
        Initialize();
        HashSet<SignedTree.Node> allNodes = [];
        Queue<SignedTree.Node> scan = new([tree.Root]);
        while (scan.TryDequeue(out SignedTree.Node node))
        {
            if (allNodes.Add(node))
            {
                foreach (SignedTree.Node child in node.Children)
                {
                    scan.Enqueue(child);
                }
            }
        }

        var nodeList = allNodes.OrderBy(n => n.Index).Select(n => n.ToRecord().Signed);
        PackedBinarySerializer s = GetSerializer();
        s.Serialize(destination, nodeList, new PackedBinarySerializationOptions(ImplicitRepeat: true));
        return Task.CompletedTask;
    }

    private PackedBinarySerializer GetSerializer()
    {
        PackedBinarySerializer s = new();
        PackedBinarySerializer.TypeBuilder nodeValueBuilder = s.AddType<NodeValue>();
        int i = 0x33;
        foreach (Type t in _valueTypes) nodeValueBuilder.AddSubType(++i, t);

        return s;
    }
}