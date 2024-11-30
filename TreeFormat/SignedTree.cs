using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using JetBrains.Annotations;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.TreeFormat;

public class SignedTree
{
    private readonly ISignedTreeTrustResolver _trustResolver;
    private DagNode _leafTrust;
    
    public SignedDirectedAcyclicGraph Graph { get; private set; }
    public DagNode Root { get; private set; }

    public SignedTree(SignedDirectedAcyclicGraph graph, ISignedTreeTrustResolver trustResolver)
    {
        Graph = graph;
        _trustResolver = trustResolver;
    }
    
    public SignedTree(TrustNodeValue rootTrust, ValueNodeValue rootValue, ISignedTreeTrustResolver trustResolver)
    {
        _trustResolver = trustResolver;
        TrustedPublicKeys keys = trustResolver.UpdateTrust(TrustedPublicKeys.None, rootTrust);
        Graph = new SignedDirectedAcyclicGraph(rootTrust, keys);
        _leafTrust = Graph.Root;
        Root = Graph.CreateNode(rootValue, keys, _leafTrust);
    }
    
    public SignedTree(ISignedTreeTrustResolver trustResolver)
    {
        Graph = null;
        _trustResolver = trustResolver;
    }

    public DagNode AddTrustNode(TrustNodeValue value)
    {
        if (Graph is null)
        {
            Graph = new SignedDirectedAcyclicGraph(value, _trustResolver.UpdateTrust(TrustedPublicKeys.None, value));
            return _leafTrust = Graph.Root;
        }

        return _leafTrust = Graph.CreateNode(value, _trustResolver.UpdateTrust(_leafTrust?.TrustedKeys ?? TrustedPublicKeys.None, value), _leafTrust);
    }

    public DagNode AddValueNode(ValueNodeValue value, DagNode parent)
    {
        return Graph.CreateNode(value, _leafTrust.TrustedKeys, _leafTrust, parent);
    }

    public DagNode SetRootValue(ValueNodeValue value)
    {
        if (Root is not null)
            throw new InvalidOperationException("Root already set");

        if (_leafTrust is null)
        {
            throw new InvalidOperationException("Must have trust value before adding value node");
        }

        return Root = Graph.CreateNode(value, _leafTrust.TrustedKeys, _leafTrust);
    }

    public DagNode ResolveConflict(DagNode forkNode, params ReadOnlySpan<DagNode> orderedPaths)
    {
        if (forkNode.Children.Count < 2)
        {
            throw new ArgumentException("Conflict nodes should have at least 2 value nodes", nameof(forkNode));
        }

        Stack<DagNode> search = new Stack<DagNode>();
        search.Push(forkNode);
        List<DagNode> leafNodes = [];
        while (search.TryPop(out var n))
        {
            if (leafNodes.LastOrDefault() == n)
            {
                continue;
            }

            if (n.Children.Count == 0)
            {
                leafNodes.Add(n);
                continue;
            }

            for (int i = n.Children.Count - 1; i >= 0; i--)
            {
                DagNode child = n.Children[i];
                search.Push(child);
            }
        }

        List<byte> indices = new List<byte>(leafNodes.Count);
        foreach (DagNode node in orderedPaths)
        {
            var i = leafNodes.IndexOf(node);
            if (i == -1)
            {
                throw new ArgumentException("Target node is not a currently conflicting leaf node of th forkNode", nameof(orderedPaths));
            }

            indices.Add((byte)i);
        }

        
        var resolution = new ConflictResolutionNodeValue(indices.ToArray());
        if (forkNode.Value is TrustNodeValue)
        {
            // The conflict is about trust, so we have to do walking
            var resolvedKeys = new LeafToRootIterable(forkNode, leafNodes).TakeWhile(n => n != forkNode)
                .Reverse()
                .Aggregate(forkNode.TrustedKeys, (k, n) => _trustResolver.UpdateTrust(k, (TrustNodeValue)n.Value));
            
            DagNode newNode = Graph.CreateNode(resolution, resolvedKeys, [forkNode, ..leafNodes]);
            return _leafTrust = newNode;
        }

        // The conflict doesn't affect trust, simple case
        return Graph.CreateNode(resolution, _leafTrust.TrustedKeys, (List<DagNode>)[forkNode, _leafTrust, ..leafNodes]);
    }

    public IEnumerable<DagNode> GetBranchIteratorFromNodeToRoot(DagNode node)
    {
        return new LeafToRootIterable(node);
    }

    public class LeafToRootIterable : IEnumerable<DagNode>
    {
        private readonly DagNode _node;
        private readonly IList<DagNode> _branches;

        public LeafToRootIterable(DagNode node)
        {
            _node = node;
        }

        public LeafToRootIterable(DagNode sharedRoot, IList<DagNode> branches)
        {
            _node = sharedRoot;
            _branches = branches;
        }

        public IEnumerator<DagNode> GetEnumerator()
        {
            return _branches is not null ? new LeafToRootIterator(_node, _branches) : new LeafToRootIterator(_node);
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    public class LeafToRootIterator : IEnumerator<DagNode>
    {
        private bool _started;
        private List<List<DagNode>> _segments;

        public LeafToRootIterator([NotNull] DagNode node)
        {
            ArgumentNullException.ThrowIfNull(node);
            
            _segments = [[node]];
        }

        public LeafToRootIterator(DagNode sharedRoot, IList<DagNode> branches)
        {
            ArgumentNullException.ThrowIfNull(sharedRoot);
            ArgumentNullException.ThrowIfNull(branches);
            _segments = [[sharedRoot, ..branches]];
        }

        public bool MoveNext()
        {
            if (_segments is null)
                return false;
            
            while (true)
            {
                DagNode node = MoveOne();
                if (node is null)
                {
                    _segments = null;
                    Current = null;
                    return false;
                }

                if (node.Value is not ConflictResolutionNodeValue conflict)
                {
                    Current = node;
                    return true;
                }
                
                switch (_segments)
                {
                    case [..[var n]]:
                        // The node we encountered was the last of a fork, we need to replace the whole fork
                        _segments.RemoveLast();
                        break;
                    case [..[.., var n]]:
                        // We just need to remove it from the leg to replace it 
                        _segments[^1].RemoveLast();
                        break;
                }

                DagNode[] branches = conflict.GetParentBranches(node, out DagNode forkNode);
                (_segments ?? []).Add([forkNode, ..branches]);
                _started = false;
            }

            DagNode MoveOne()
            {
                if (!_started)
                {
                    _started = true;
                    return _segments[^1][^1];
                }

                switch (_segments)
                {
                    case [[var node]]:
                    {
                        return _segments[0][0] = GetTreeParent(node);
                    }
                    case [.., [_]]:
                    {
                        _segments.RemoveLast();
                        return _segments[^1][^1];
                    }
                    case [.., [var root, .., var node] leg]:
                    {
                        var parent = GetTreeParent(node);
                        if (parent == root)
                        {
                            leg.RemoveLast();
                            return leg[^1];
                        }
                        
                        return leg[^1] = parent;
                    }
                    default:
                        throw new InvalidOperationException();
                }
            }

            DagNode GetTreeParent(DagNode node)
            {
                // Trust nodes just have single parents
                if (node.Value is TrustNodeValue)
                {
                    return node.Parents is [var p, ..] ? p : null;
                }

                // Non-trust nodes always have a trust parent first, skip it
                {
                    return node.Parents is [_, var p, ..] ? p : null;
                }
            }
        }

        public void Reset()
        {
            throw new NotSupportedException();
        }

        public DagNode Current { get; private set; }

        object IEnumerator.Current => Current;
        
        public void Dispose()
        {
        }
    }

    [PackedBinarySerializable]
    public abstract class TrustNodeValue : NodeValue
    {
    }

    [PackedBinarySerializable]
    public abstract class ValueNodeValue : NodeValue
    {
    }

    [PackedBinarySerializable]
    private class ConflictResolutionNodeValue : NodeValue
    {
        private readonly ReadOnlyMemory<byte> _order;

        public ConflictResolutionNodeValue(params byte[] forkOrder)
        {
            _order = forkOrder;
        }

        public override bool TryGetDataToSign(Span<byte> destination, out int cb)
        {
            cb = _order.Length;
            return _order.Span.TryCopyTo(destination);
        }

        public DagNode[] GetParentBranches(
            DagNode conflictNode,
            out DagNode forkNode
        )
        {
            if (conflictNode.Value != this)
            {
                throw new ArgumentException("Not a valid conflict node", nameof(conflictNode));
            }

            var parents = conflictNode.Parents;
            forkNode = parents[0];
            int offset = 2;
            if (forkNode.Value is TrustNodeValue)
            {
                // Trust nodes don't have independent trust nodes
                offset = 1;
            }

            DagNode[] branches = new DagNode[_order.Length];
            var span = _order.Span;
            for (int i = 0; i < span.Length; i++)
            {
                branches[i] = parents[span[i] + offset];
            }

            return branches;
        }
    }
}

public interface ISignedTreeTrustResolver
{
    TrustedPublicKeys UpdateTrust(TrustedPublicKeys parentTrust, SignedTree.TrustNodeValue nodeValue);
}

public static class ListExtensions
{
    public static void RemoveLast<T>(this List<T> list)
    {
        list.RemoveAt(list.Count - 1);
    }
}