using System;
using System.Collections.Generic;
using System.Linq;
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

    public DagNode Root { get; }

    public DagNode CreateNode(Validated<NodeRecord> record, TrustedPublicKeys trustedPublicKeys, params IEnumerable<DagNode> parents)
    {
        SignedRecordNode node = new(record, trustedPublicKeys, Count++, parents);
        return node;
    }

    public DagNode CreateNode(NodeValue value, TrustedPublicKeys trustedPublicKeys, params IEnumerable<DagNode> parents)
    {
        SignedRecordNode node = new(value, trustedPublicKeys, Count++);
        AddNode(node, parents);
        return node;
    }

    public void AddNode(DagNode child, params IEnumerable<DagNode> parents)
    {
        SignedRecordNode signedChild = (SignedRecordNode)child;
        foreach (DagNode node in parents)
        {
            SignedRecordNode parent = (SignedRecordNode)node;
            parent.AddChild(signedChild);
        }
    }

    private class SignedRecordNode : DagNode
    {
        private List<SignedRecordNode> _children;
        private List<SignedRecordNode> _parents;
        private Validated<NodeRecord> _record;
        private readonly NodeValue _value;

        public SignedRecordNode(Validated<NodeRecord> record, TrustedPublicKeys trustedKeys, int index, IEnumerable<DagNode> parents) : base(trustedKeys, index)
        {
            _value = record.Value.Value;
            foreach (DagNode node in parents)
            {
                SignedRecordNode parent = (SignedRecordNode)node;
                parent.AddChild(this);
            }
            // This needs to be set after the children are added, because adding a parent deletes _record
            _record = record;
        }
        
        public SignedRecordNode(NodeValue value, TrustedPublicKeys trustedKeys, int index) : base(trustedKeys, index)
        {
            _value = value;
        }
        
        public override NodeValue Value => _value;
        public override IReadOnlyList<DagNode> Parents => (IReadOnlyList<DagNode>)_parents?.AsReadOnly() ?? Array.Empty<DagNode>();
        public override IReadOnlyList<DagNode> Children => (IReadOnlyList<DagNode>)_children?.AsReadOnly() ?? Array.Empty<DagNode>();
        
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
}

public abstract class DagNode
{
    protected DagNode(TrustedPublicKeys trustedKeys, int index)
    {
        TrustedKeys = trustedKeys;
        Index = index;
    }

    public abstract NodeValue Value { get; }
    public TrustedPublicKeys TrustedKeys { get; }

    public abstract IReadOnlyList<DagNode> Parents { get; }
    public abstract IReadOnlyList<DagNode> Children { get; }
        
    public int Index { get; }

    public abstract Validated<NodeRecord> ToRecord(PrivateKeyInfo signer, VaultCryptographyAlgorithm algorithm);
}

public interface ISignedDirectedAcyclicGraphTrustResolver
{
    TrustedPublicKeys UpdateTrustedKeys(IReadOnlyList<DagNode> fromNodes, NodeValue value);
}

public class CallbackTrustResolver : ISignedDirectedAcyclicGraphTrustResolver
{
    private readonly Func<IReadOnlyList<DagNode>, NodeValue, TrustedPublicKeys> _callback;

    public CallbackTrustResolver(Func<IReadOnlyList<DagNode>, NodeValue, TrustedPublicKeys> callback)
    {
        _callback = callback;
    }

    public TrustedPublicKeys UpdateTrustedKeys(IReadOnlyList<DagNode> fromNodes, NodeValue value) => _callback(fromNodes, value);
}