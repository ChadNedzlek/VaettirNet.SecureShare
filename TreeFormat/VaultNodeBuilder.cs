using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using VaettirNet.PackedBinarySerialization;
using VaettirNet.SecureShare.Common;
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

    public SignedDirectedAcyclicGraph BuildTree(
        IEnumerable<Signed<NodeRecord>> records,
        Func<IReadOnlyList<SignedDirectedAcyclicGraph.Node>, NodeValue, TrustedPublicKeys> establishTrust,
        VaultCryptographyAlgorithm alg
    )
    {
        Dictionary<ReadOnlyMemory<byte>, SignedDirectedAcyclicGraph.Node> nodes = new(MemoryComparer<byte>.Default);
        SignedDirectedAcyclicGraph directedAcyclicGraph = null;
        foreach (Signed<NodeRecord> signed in records)
        {
            NodeRecord record = signed.DangerousGetPayload();
            List<SignedDirectedAcyclicGraph.Node> parents = record.ParentSignatures.Select(sig => nodes[sig]).ToList();

            TrustedPublicKeys keys = establishTrust(parents, record.Value);
            SignedDirectedAcyclicGraph.Node newNode;
            if (directedAcyclicGraph is null)
            {
                directedAcyclicGraph = new SignedDirectedAcyclicGraph(signed.Validate(keys.Get(signed.Signer).SigningKey.Span, alg), keys);
                newNode = directedAcyclicGraph.Root;
            }
            else
            {
                if (parents.Count == 0) throw new ArgumentException("Multiple root nodes detected", nameof(nodes));
                
                newNode = directedAcyclicGraph.CreateNode(signed.Validate(keys.Get(signed.Signer).SigningKey.Span, alg), keys);
            }
            nodes.Add(signed.Signature, newNode);
        }

        if (directedAcyclicGraph is null) throw new ArgumentException("No root node detected", nameof(nodes));

        return directedAcyclicGraph;
    }

    public VaultNodeBuilder AddNodeType<T>()
    {
        _valueTypes.Add(typeof(T));
        return this;
    }

    public Task<SignedDirectedAcyclicGraph> ReadTreeAsync(
        Stream source,
        Func<IReadOnlyList<SignedDirectedAcyclicGraph.Node>, NodeValue, TrustedPublicKeys> establishTrust,
        VaultCryptographyAlgorithm alg
    )
    {
        PackedBinarySerializer s = GetSerializer();
        Signed<NodeRecord>[] records = s.Deserialize<Signed<NodeRecord>[]>(source, new PackedBinarySerializationOptions(ImplicitRepeat: true));
        return Task.FromResult(BuildTree(records, establishTrust, alg));
    }

    public Task WriteTreeAsync(
        SignedDirectedAcyclicGraph directedAcyclicGraph,
        Stream destination,
        PrivateKeyInfo privateKeyInfo,
        VaultCryptographyAlgorithm algorithm
    )
    {
        Initialize();
        HashSet<SignedDirectedAcyclicGraph.Node> allNodes = [];
        Queue<SignedDirectedAcyclicGraph.Node> scan = new([directedAcyclicGraph.Root]);
        while (scan.TryDequeue(out SignedDirectedAcyclicGraph.Node node))
        {
            if (allNodes.Add(node)) 
            {
                foreach (SignedDirectedAcyclicGraph.Node child in node.Children)
                {
                    scan.Enqueue(child);
                }
            }
        }

        var nodeList = allNodes.OrderBy(n => n.Index).Select(n => n.ToRecord(privateKeyInfo, algorithm).Signed);
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