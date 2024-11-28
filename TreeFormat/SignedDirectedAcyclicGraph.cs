using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using VaettirNet.SecureShare.Common;
using VaettirNet.SecureShare.Crypto;

namespace VaettirNet.TreeFormat;

public class SignedDirectedAcyclicGraph
{
    public int Count { get; private set; } = 1;
    
    public SignedDirectedAcyclicGraph(Validated<NodeRecord> record, TrustedPublicKeys trustedPublicKeys)
    {
        Root = new SignedRecordNode(record, trustedPublicKeys, 0, []);
    }
    
    public SignedDirectedAcyclicGraph(NodeValue value, TrustedPublicKeys trustedPublicKeys)
    {
        Root = new SignedRecordNode(value, trustedPublicKeys, 0);
    }

    public Node Root { get; }

    public Node CreateNode(Validated<NodeRecord> record, TrustedPublicKeys trustedPublicKeys, params IEnumerable<Node> parents)
    {
        SignedRecordNode node = new(record, trustedPublicKeys, Count++, parents);
        return node;
    }

    public Node CreateNode(NodeValue value, TrustedPublicKeys trustedPublicKeys, params IEnumerable<Node> parents)
    {
        SignedRecordNode node = new(value, trustedPublicKeys, Count++);
        AddNode(node, parents);
        return node;
    }

    public void AddNode(Node child, params IEnumerable<Node> parents)
    {
        SignedRecordNode signedChild = (SignedRecordNode)child;
        foreach (Node node in parents)
        {
            SignedRecordNode parent = (SignedRecordNode)node;
            parent.AddChild(signedChild);
        }
    }

    public abstract class Node
    {
        protected Node(TrustedPublicKeys trustedKeys, int index)
        {
            TrustedKeys = trustedKeys;
            Index = index;
        }

        public abstract NodeValue Value { get; }
        public TrustedPublicKeys TrustedKeys { get; }

        public abstract IReadOnlyList<Node> Parents { get; }
        public abstract IReadOnlyList<Node> Children { get; }
        
        public int Index { get; }

        public abstract Validated<NodeRecord> ToRecord(PrivateKeyInfo signer, VaultCryptographyAlgorithm algorithm);
    }

    private class SignedRecordNode : Node
    {
        private List<SignedRecordNode> _children;
        private List<SignedRecordNode> _parents;
        private Validated<NodeRecord> _record;
        private readonly NodeValue _value;
        private bool _recordValid = false;

        public SignedRecordNode(Validated<NodeRecord> record, TrustedPublicKeys trustedKeys, int index, IEnumerable<Node> parents) : base(trustedKeys, index)
        {
            _value = record.Value.Value;
            foreach (Node node in parents)
            {
                SignedRecordNode parent = (SignedRecordNode)node;
                parent.AddChild(this);
            }
            _record = record;
        }
        
        public SignedRecordNode(NodeValue value, TrustedPublicKeys trustedKeys, int index) : base(trustedKeys, index)
        {
            _value = value;
        }
        
        public override NodeValue Value => _value;
        public override IReadOnlyList<Node> Parents => (IReadOnlyList<Node>)_parents?.AsReadOnly() ?? Array.Empty<Node>();
        public override IReadOnlyList<Node> Children => (IReadOnlyList<Node>)_children?.AsReadOnly() ?? Array.Empty<Node>();
        
        public override Validated<NodeRecord> ToRecord(PrivateKeyInfo signer, VaultCryptographyAlgorithm algorithm)
        {
            if (!_record.IsEmpty)
            {
                return _record;
            }

            return _record = algorithm.Sign(new NodeRecord(_value, Parents.Select(p => p.ToRecord(signer, algorithm).Signature)), signer);
        }

        public void AddChild(SignedRecordNode child)
        {
            (_children ??= []).Add(child);
            (child._parents ??= []).Add(this);
            
            
            // Parents are part of the signature, so adding a child invalidates it
            child._record = default;
        }

        public override string ToString()
        {
            if (_record.IsEmpty)
            {
                return $"{Index} : pending = {Value}";
            }

            return $"{Index} : {Convert.ToBase64String(_record.Signature.Span)} = {Value}";
        }
    }

    public readonly struct NodeId : IEquatable<NodeId>
    {
        internal NodeId(ReadOnlyMemory<byte> signature)
        {
            Signature = signature;
        }

        internal ReadOnlyMemory<byte> Signature { get; }

        public bool Equals(NodeId other)
        {
            return MemoryComparer<byte>.Default.Equals(Signature, other.Signature);
        }

        public override bool Equals(object obj)
        {
            return obj is NodeId other && Equals(other);
        }

        public override int GetHashCode()
        {
            return MemoryComparer<byte>.Default.GetHashCode(Signature);
        }
    }
}