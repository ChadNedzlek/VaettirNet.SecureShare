using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace TreeFormat;

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

    public VaultNode BuildTree(IEnumerable<NodeRecord> records)
    {
        Dictionary<ReadOnlyMemory<byte>, VaultNode> nodes = new(BufferComparer.Instance);
        VaultNode root = null;
        foreach (NodeRecord? record in records)
        {
            VaultNode? parent = null;
            if (!record.Parent.IsEmpty) parent = nodes[record.Parent];

            VaultNode node = (VaultNode)Activator.CreateInstance(
                typeof(VaultNode<>).MakeGenericType(record.Value.GetType()),
                parent,
                record.Value,
                record.Signature,
                nodes.Count
            )!;
            nodes.Add(record.Signature, node);
            if (node.Parent is null)
            {
                if (root != null) throw new ArgumentException("Multiple root nodes detected", nameof(nodes));

                root = node;
            }
        }

        if (root is null) throw new ArgumentException("No root node detected", nameof(nodes));

        return root;
    }

    public VaultNodeBuilder AddNodeType<T>()
    {
        _valueTypes.Add(typeof(T));
        return this;
    }

    public async Task<VaultNode> ReadTreeAsync(Stream source)
    {
        throw null;
    }

    public async Task WriteTreeAsync(VaultNode tree, Stream destination)
    {
        Initialize();
        HashSet<VaultNode> allNodes = [];
        Queue<VaultNode> scan = new([tree]);
        while (scan.TryDequeue(out VaultNode? node))
            if (allNodes.Add(node))
                foreach (VaultNode? child in node.Children)
                    scan.Enqueue(child);

        IEnumerable<VaultNode>? newNodes = allNodes.Where(n => n.Index == -1);
        IOrderedEnumerable<VaultNode>? oldNodes = allNodes.Where(n => n.Index > -1).OrderBy(n => n.Index);
        NodeRecord[] nodeList = [..oldNodes.Concat(newNodes).Select(n => new NodeRecord(n.Parent?.Signature ?? default, n.Signature, n.GetValue()))];
        throw null;
    }
}