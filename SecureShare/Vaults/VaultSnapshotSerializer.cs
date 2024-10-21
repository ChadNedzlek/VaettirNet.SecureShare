using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using ProtoBuf.Meta;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

public class VaultSnapshotSerializer
{
    private readonly ProtobufObjectSerializer<Signed<VaultDataSnapshot>> _serializer;

    public VaultSnapshotSerializer(params IEnumerable<Type> sealedSecretTypes)
    {
        _serializer = ProtobufObjectSerializer<Signed<VaultDataSnapshot>>.Create(
            model =>
            {
                AddSignedType<ClientModificationRecord>(model);
                AddSignedType<RemovedSecretRecord>(model);
                var sealedValueType = model.Add<UntypedSealedSecret>();
                int fieldNumber = 20;
                foreach (Type type in sealedSecretTypes)
                {
                    sealedValueType.AddSubType(fieldNumber++, type).UseConstructor = false;
                }

                void AddSignedType<T>(RuntimeTypeModel runtimeTypeModel) where T : ISignable
                {
                    runtimeTypeModel.Add<Signed<T>>();
                }
            }
        );
    }

    public void Serialize(Stream destination, Signed<VaultDataSnapshot> snapshot)
    {
        _serializer.Serialize(destination, snapshot);
    }

    public Signed<VaultDataSnapshot> Deserialize(Stream source)
    {
        return _serializer.Deserialize(source);
    }

    public static Builder CreateBuilder() => new Builder(ImmutableList<Type>.Empty);

    public class Builder
    {
        public readonly ImmutableList<Type> SecretTypes;

        public Builder(ImmutableList<Type> secretTypes)
        {
            SecretTypes = secretTypes;
        }

        public Builder WithSecret<TAttribute, TProtected>()
            where TAttribute : IBinarySerializable<TAttribute>, IJsonSerializable<TAttribute>
            where TProtected : IBinarySerializable<TProtected>
        {
            return new Builder(SecretTypes.Add(typeof(SealedSecretSecret<TAttribute, TProtected>)));
        }

        public VaultSnapshotSerializer Build()
        {
            return new VaultSnapshotSerializer(SecretTypes);
        }
    }
}