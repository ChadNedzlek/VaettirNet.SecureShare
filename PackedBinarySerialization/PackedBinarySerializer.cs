using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.Pipelines;
using System.Text;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.PackedBinarySerialization.Buffers;

namespace VaettirNet.PackedBinarySerialization;

public record class PackedBinarySerializationOptions(Encoding? Encoding = null, bool UsePackedEncoding = false, bool ImplicitRepeat = false);

public class PackedBinarySerializer
{
    public class TypeBuilder
    {
        private readonly PackedBinarySerializer _serializer;
        private readonly Type _type;

        public TypeBuilder(Type type, PackedBinarySerializer serializer)
        {
            _serializer = serializer;
            _type = type;
        }

        public TypeBuilder AddSubType<TDerived>(int tag) => AddSubType(tag, typeof(TDerived));
        public TypeBuilder AddSubType(int tag, Type derived)
        {
            _serializer.AddSubType(_type, derived, tag);
            return new TypeBuilder(derived, _serializer);
        }

        public TypeBuilder WithAttribute(PackedBinarySerializableAttribute attribute)
        {
            _serializer._effectiveAttributes[_type] = attribute;
            return this;
        }

        public TypeBuilder WithMemberLayout(PackedBinaryMemberLayout memberLayout)
        {
            var attr = _serializer._effectiveAttributes[_type];
            _serializer._effectiveAttributes[_type] =
                new PackedBinarySerializableAttribute { MemberLayout = memberLayout, IncludeNonPublic = attr.IncludeNonPublic };
            return this;
        }

        public TypeBuilder IncludeNonPublicMembers(bool include = true)
        {
            var attr = _serializer._effectiveAttributes[_type];
            _serializer._effectiveAttributes[_type] =
                new PackedBinarySerializableAttribute { MemberLayout = attr.MemberLayout, IncludeNonPublic = include };
            return this;
        }
    }

    private PackedBinarySerializationContext BuildContext(PackedBinarySerializationOptions? options)
    {
        if (options == null)
            return default;
        return new PackedBinarySerializationContext(options.Encoding, default, options.ImplicitRepeat, options.UsePackedEncoding);
    }

    public void Serialize<T>(Stream s, T value, PackedBinarySerializationOptions? options = null)
    {
        PipeWriter writer = PipeWriter.Create(s);
        SerializeCore(ref writer, value, BuildContext(options));
    }

    private void SerializeCore<TWriter, T>(ref TWriter writer, T value, PackedBinarySerializationContext ctx)
        where TWriter : IBufferWriter<byte>
    {
        new PackedBinaryWriter<TWriter>(this, writer).Write(value, ctx);
    }
    
    private void SerializeCore<TWriter, T>(ref TWriter writer, Type type, T value, PackedBinarySerializationContext ctx)
        where TWriter : IBufferWriter<byte>
    {
        new PackedBinaryWriter<TWriter>(this, writer).Write(type, value, ctx);
    }

    public void Serialize<T>(IBufferWriter<byte> b, T value, PackedBinarySerializationOptions? options = null)
    {
        SerializeCore(ref b, value, BuildContext(options));
    }
    
    public void Serialize(Stream s, Type type, object value, PackedBinarySerializationOptions? options = null)
    {
        PipeWriter writer = PipeWriter.Create(s);
        SerializeCore(ref writer, value, BuildContext(options));
        writer.Complete();
    }

    public void Serialize(IBufferWriter<byte> b, Type type, object value, PackedBinarySerializationOptions? options = null)
    {
        SerializeCore(ref b, value, BuildContext(options));
    }

    public T Deserialize<T>(Stream stream, PackedBinarySerializationOptions? options = null)
    {
        StreamBufferReader reader = new(stream);
        return DeserializeCore<T, StreamBufferReader>(ref reader, typeof(T), BuildContext(options));
    }

    public T Deserialize<T>(IBufferReader<byte> b, PackedBinarySerializationOptions? options = null)
    {
        return DeserializeCore<T, IBufferReader<byte>>(ref b, typeof(T), BuildContext(options));
    }
    
    public T Deserialize<T>(ReadOnlySpan<byte> b, PackedBinarySerializationOptions? options = null) where T:allows ref struct
    {
        SpanBufferReader<byte> reader = new(b);
        return DeserializeCore<T, SpanBufferReader<byte>>(ref reader, typeof(T), BuildContext(options));
    }

    public object Deserialize(Stream stream, Type type, PackedBinarySerializationOptions? options = null)
    {
        StreamBufferReader reader = new(stream);
        return DeserializeCore<object, StreamBufferReader>(ref reader, type, BuildContext(options));
    }

    public object Deserialize(IBufferReader<byte> b, Type type, PackedBinarySerializationOptions? options = null)
    {
        return DeserializeCore<object, IBufferReader<byte>>(ref b, type, BuildContext(options));
    }
    
    private T DeserializeCore<T, TReader>(scoped ref TReader reader, Type type, PackedBinarySerializationContext ctx)
        where TReader : IBufferReader<byte>, allows ref struct
        where T : allows ref struct
    {
        return new PackedBinaryReader<TReader>(this, reader).Read<T>(type, ctx);
    }
    
    internal int MetadataRevision { get; private set; } = 1;

    private readonly Dictionary<Type, Dictionary<int, Type>> _tagToType = [];
    private readonly Dictionary<Type, Dictionary<Type, int>> _typeToTag = [];
    
    internal Dictionary<Type, int>? GetSubtypeTags(Type baseClass)
    {
        return _typeToTag.GetValueOrDefault(baseClass);
    }
    internal Dictionary<int, Type>? GetTagSubtypes(Type baseClass)
    {
        return _tagToType.GetValueOrDefault(baseClass);
    }

    public TypeBuilder AddType<T>() => AddType(typeof(T));
    public TypeBuilder AddType(Type type)
    {
        _effectiveAttributes.Add(type, new PackedBinarySerializableAttribute());
        return new TypeBuilder(type, this);
    }

    private PackedBinarySerializer AddSubType<TBase, TDerived>(int tag) where TDerived : TBase => AddSubType(typeof(TBase), typeof(TDerived), tag);
    private PackedBinarySerializer AddSubType(Type baseClass, Type derived, int tag)
    {
        MetadataRevision++;
        _tagToType.GetOrAdd(baseClass).Add(tag, derived);
        _typeToTag.GetOrAdd(baseClass).Add(derived, tag);
        _effectiveAttributes.GetOrAdd(derived, _ => new PackedBinarySerializableAttribute());
        return this;
    }

    private readonly Dictionary<Type, (Type targetType, Delegate transform)> _writeSurrogate = [];
    private readonly Dictionary<Type, (Type targetType, Delegate transform)> _readSurrogate = [];

    public PackedBinarySerializer SetSurrogate<TModel, TSerialized>(Func<TModel, TSerialized> fromModel, Func<TSerialized, TModel> toModel)
    {
        _writeSurrogate.Add(typeof(TModel), (typeof(TSerialized), fromModel));
        _readSurrogate.Add(typeof(TModel), (typeof(TSerialized), toModel));
        return this;
    }

    internal bool TryGetWriteSurrogate(Type modelType, [NotNullWhen(true)] out Type? targetType, [NotNullWhen(true)] out Delegate? transform)
    {
        if (_writeSurrogate.TryGetValue(modelType, out var surrogate))
        {
            targetType = surrogate.targetType;
            transform = surrogate.transform;
            return true;
        }

        targetType = null;
        transform = null;
        return false;
    }
    
    internal bool TryGetReadSurrogate(Type modelType, [NotNullWhen(true)] out Type? targetType, [NotNullWhen(true)] out Delegate? transform)
    {
        if (_readSurrogate.TryGetValue(modelType, out var surrogate))
        {
            targetType = surrogate.targetType;
            transform = surrogate.transform;
            return true;
        }

        targetType = null;
        transform = null;
        return false;
    }

    private readonly Dictionary<Type, PackedBinarySerializableAttribute> _effectiveAttributes = [];
    public PackedBinarySerializableAttribute? GetEffectiveSerializableAttribute(Type type)
    {
        return _effectiveAttributes.GetValueOrDefault(type);
    }
}

internal static class DictionaryExtensions
{
    public static TValue GetOrAdd<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key, Func<TKey, TValue> create)
    {
        if (!dictionary.TryGetValue(key, out TValue? value))
        {
            dictionary.Add(key, value = create(key));
        }

        return value;
    }
    
    public static TValue GetOrAdd<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key) where TValue : new()
    {
        if (!dictionary.TryGetValue(key, out TValue? value))
        {
            dictionary.Add(key, value = new());
        }

        return value;
    }
}