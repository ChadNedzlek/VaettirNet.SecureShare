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

    private SignedDirectedAcyclicGraph BuildTree(
        IReadOnlyList<Signed<NodeRecord>> records,
        ISignedDirectedAcyclicGraphTrustResolver trustResolver,
        VaultCryptographyAlgorithm alg
    )
    {
        Dictionary<ReadOnlyMemory<byte>, DagNode> nodes = new(MemoryComparer<byte>.Default);
        SignedDirectedAcyclicGraph directedAcyclicGraph = null;
        for (int i = 0; i < records.Count; i++)
        {
            Signed<NodeRecord> signed = records[i];
            NodeRecord record = signed.DangerousGetPayload();
            List<DagNode> parents = record.ParentSignatures.Select(sig => nodes[sig]).ToList();

            TrustedPublicKeys keys = trustResolver.UpdateTrustedKeys(parents, record.Value);
            DagNode newNode;
            if (directedAcyclicGraph is null)
            {
                directedAcyclicGraph = new SignedDirectedAcyclicGraph(signed.Validate(keys.Get(signed.Signer).SigningKey.Span, alg), keys);
                newNode = directedAcyclicGraph.Root;
            }
            else
            {
                if (parents.Count == 0) throw new ArgumentException("Multiple root nodes detected", nameof(nodes));

                newNode = directedAcyclicGraph.CreateNode(signed.Validate(keys.Get(signed.Signer).SigningKey.Span, alg), keys, parents);
            }

            if (newNode.Index != i)
            {
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
        Func<IReadOnlyList<DagNode>, NodeValue, TrustedPublicKeys> establishTrust,
        VaultCryptographyAlgorithm alg
    ) => ReadTreeAsync(source, new CallbackTrustResolver(establishTrust), alg); 
    
    public Task<SignedDirectedAcyclicGraph> ReadTreeAsync(
        Stream source,
        ISignedDirectedAcyclicGraphTrustResolver trustResolver,
        VaultCryptographyAlgorithm alg
    )
    {
        PackedBinarySerializer s = GetSerializer();
        Signed<NodeRecord>[] records = s.Deserialize<Signed<NodeRecord>[]>(source, new PackedBinarySerializationOptions(ImplicitRepeat: true));
        return Task.FromResult(BuildTree(records, trustResolver, alg));
    }

    public Task WriteTreeAsync(
        SignedDirectedAcyclicGraph directedAcyclicGraph,
        Stream destination,
        PrivateKeyInfo privateKeyInfo,
        VaultCryptographyAlgorithm algorithm
    )
    {
        Initialize();
        HashSet<DagNode> allNodes = [];
        Queue<DagNode> scan = new([directedAcyclicGraph.Root]);
        while (scan.TryDequeue(out DagNode node))
        {
            if (allNodes.Add(node)) 
            {
                foreach (DagNode child in node.Children)
                {
                    scan.Enqueue(child);
                }
            }
        }

        List<Signed<NodeRecord>> nodeList = allNodes.OrderBy(n => n.Index).Select(n => n.ToRecord(privateKeyInfo, algorithm).Signed).ToList();
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