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
    private readonly Dictionary<Type, PackedBinarySerializableAttribute> _effectiveAttributes = [];
    private readonly Dictionary<Type, (Type targetType, Delegate transform)> _readSurrogate = [];

    private readonly Dictionary<Type, Dictionary<int, Type>> _tagToType = [];
    private readonly Dictionary<Type, Dictionary<Type, int>> _typeToTag = [];

    private readonly Dictionary<Type, (Type targetType, Delegate transform)> _writeSurrogate = [];

    internal int MetadataRevision { get; private set; } = 1;

    private PackedBinarySerializationContext BuildContext(PackedBinarySerializationOptions? options)
    {
        if (options == null)
            return default;
        return new PackedBinarySerializationContext(options.Encoding, default, options.ImplicitRepeat, options.UsePackedEncoding);
    }

    public void Serialize<T>(Stream s, T value, PackedBinarySerializationOptions? options = null)
    {
        PipeWriter writer = PipeWriter.Create(s, new StreamPipeWriterOptions(leaveOpen: true));
        SerializeCore(ref writer, value, BuildContext(options));
        writer.Complete();
    }

    private void SerializeCore<TWriter, T>(ref TWriter writer, T value, PackedBinarySerializationContext ctx)
        where TWriter : IBufferWriter<byte>
    {
        new PackedBinaryWriter<TWriter>(this, writer).Write(value, ctx);
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

    public T Deserialize<T>(ReadOnlySpan<byte> b, PackedBinarySerializationOptions? options = null)
        where T : allows ref struct
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

    internal Dictionary<Type, int>? GetSubtypeTags(Type baseClass)
    {
        return _typeToTag.GetValueOrDefault(baseClass);
    }

    internal Dictionary<int, Type>? GetTagSubtypes(Type baseClass)
    {
        return _tagToType.GetValueOrDefault(baseClass);
    }

    public TypeBuilder AddType<T>()
    {
        return AddType(typeof(T));
    }

    public TypeBuilder AddType(Type type)
    {
        _effectiveAttributes.Add(type, new PackedBinarySerializableAttribute());
        return new TypeBuilder(type, this);
    }

    private void AddSubType(Type baseClass, Type derived, int tag)
    {
        MetadataRevision++;
        _tagToType.GetOrAdd(baseClass).Add(tag, derived);
        _typeToTag.GetOrAdd(baseClass).Add(derived, tag);
        _effectiveAttributes.GetOrAdd(derived, _ => new PackedBinarySerializableAttribute());
    }

    public PackedBinarySerializer SetSurrogate<TModel, TSerialized>(Func<TModel, TSerialized> fromModel, Func<TSerialized, TModel> toModel)
    {
        _writeSurrogate.Add(typeof(TModel), (typeof(TSerialized), fromModel));
        _readSurrogate.Add(typeof(TModel), (typeof(TSerialized), toModel));
        return this;
    }

    internal bool TryGetWriteSurrogate(Type modelType, [NotNullWhen(true)] out Type? targetType, [NotNullWhen(true)] out Delegate? transform)
    {
        if (_writeSurrogate.TryGetValue(modelType, out (Type targetType, Delegate transform) surrogate))
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
        if (_readSurrogate.TryGetValue(modelType, out (Type targetType, Delegate transform) surrogate))
        {
            targetType = surrogate.targetType;
            transform = surrogate.transform;
            return true;
        }

        targetType = null;
        transform = null;
        return false;
    }

    public PackedBinarySerializableAttribute? GetEffectiveSerializableAttribute(Type type)
    {
        return _effectiveAttributes.GetValueOrDefault(type);
    }

    public class TypeBuilder
    {
        private readonly PackedBinarySerializer _serializer;
        private readonly Type _type;

        public TypeBuilder(Type type, PackedBinarySerializer serializer)
        {
            _serializer = serializer;
            _type = type;
        }

        public TypeBuilder AddSubType<TDerived>(int tag)
        {
            return AddSubType(tag, typeof(TDerived));
        }

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
            PackedBinarySerializableAttribute attr = _serializer._effectiveAttributes[_type];
            _serializer._effectiveAttributes[_type] =
                new PackedBinarySerializableAttribute { MemberLayout = memberLayout, IncludeNonPublic = attr.IncludeNonPublic };
            return this;
        }

        public TypeBuilder IncludeNonPublicMembers(bool include = true)
        {
            PackedBinarySerializableAttribute attr = _serializer._effectiveAttributes[_type];
            _serializer._effectiveAttributes[_type] =
                new PackedBinarySerializableAttribute { MemberLayout = attr.MemberLayout, IncludeNonPublic = include };
            return this;
        }
    }
}

internal static class DictionaryExtensions
{
    public static TValue GetOrAdd<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key, Func<TKey, TValue> create)
    {
        if (!dictionary.TryGetValue(key, out TValue? value)) dictionary.Add(key, value = create(key));

        return value;
    }

    public static TValue GetOrAdd<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key)
        where TValue : new()
    {
        if (!dictionary.TryGetValue(key, out TValue? value)) dictionary.Add(key, value = new TValue());

        return value;
    }
}

public delegate TOut RefInFunc<T1, out TOut>(scoped ref T1 refArg)
    where T1 : allows ref struct
    where TOut : allows ref struct;
public delegate TOut RefInFunc<T1, in T2, out TOut>(scoped ref T1 refArg, T2 arg2)
    where T1 : allows ref struct
    where T2 : allows ref struct
    where TOut : allows ref struct;
public delegate TOut RefInFunc<T1, in T2, in T3, out TOut>(scoped ref T1 refArg, T2 arg2, T3 arg3)
    where T1 : allows ref struct
    where T2 : allows ref struct
    where T3 : allows ref struct
    where TOut : allows ref struct;
public delegate TOut RefInFunc<T1, in T2, in T3, in T4, out TOut>(scoped ref T1 refArg, T2 arg2, T3 arg3, T4 arg4)
    where T1 : allows ref struct
    where T2 : allows ref struct
    where T3 : allows ref struct
    where T4 : allows ref struct
    where TOut : allows ref struct;
public delegate TOut RefInFunc<T1, in T2, in T3, in T4, in T5, out TOut>(scoped ref T1 refArg, T2 arg2, T3 arg3, T4 arg4, T5 arg5)
    where T1 : allows ref struct
    where T2 : allows ref struct
    where T3 : allows ref struct
    where T4 : allows ref struct
    where T5 : allows ref struct
    where TOut : allows ref struct;
public delegate TOut RefInFunc<T1, in T2, in T3, in T4, in T5, in T6, out TOut>(scoped ref T1 refArg, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6)
    where T1 : allows ref struct
    where T2 : allows ref struct
    where T3 : allows ref struct
    where T4 : allows ref struct
    where T5 : allows ref struct
    where T6 : allows ref struct
    where TOut : allows ref struct;
public delegate TOut RefInFunc<T1, in T2, in T3, in T4, in T5, in T6, in T7, out TOut>(scoped ref T1 refArg, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6, T7 arg7)
    where T1 : allows ref struct
    where T2 : allows ref struct
    where T3 : allows ref struct
    where T4 : allows ref struct
    where T5 : allows ref struct
    where T6 : allows ref struct
    where T7 : allows ref struct
    where TOut : allows ref struct;
public delegate TOut RefInFunc<T1, in T2, in T3, in T4, in T5, in T6, in T7, in T8, out TOut>(scoped ref T1 refArg, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6, T7 arg7, T8 arg8)
    where T1 : allows ref struct
    where T2 : allows ref struct
    where T3 : allows ref struct
    where T4 : allows ref struct
    where T5 : allows ref struct
    where T6 : allows ref struct
    where T7 : allows ref struct
    where T8 : allows ref struct
    where TOut : allows ref struct;

public delegate void RefInAction<T1>(scoped ref T1 refArg)
    where T1 : allows ref struct;
public delegate void RefInAction<T1, in T2>(scoped ref T1 refArg, T2 arg2)
    where T1 : allows ref struct
    where T2 : allows ref struct;
public delegate void RefInAction<T1, in T2, in T3>(scoped ref T1 refArg, T2 arg2, T3 arg3)
    where T1 : allows ref struct
    where T2 : allows ref struct
    where T3 : allows ref struct;
public delegate void RefInAction<T1, in T2, in T3, in T4>(scoped ref T1 refArg, T2 arg2, T3 arg3, T4 arg4)
    where T1 : allows ref struct
    where T2 : allows ref struct
    where T3 : allows ref struct
    where T4 : allows ref struct;
public delegate void RefInAction<T1, in T2, in T3, in T4, in T5>(scoped ref T1 refArg, T2 arg2, T3 arg3, T4 arg4, T5 arg5)
    where T1 : allows ref struct
    where T2 : allows ref struct
    where T3 : allows ref struct
    where T4 : allows ref struct
    where T5 : allows ref struct;
public delegate void RefInAction<T1, in T2, in T3, in T4, in T5, in T6>(scoped ref T1 refArg, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6)
    where T1 : allows ref struct
    where T2 : allows ref struct
    where T3 : allows ref struct
    where T4 : allows ref struct
    where T5 : allows ref struct
    where T6 : allows ref struct;
public delegate void RefInAction<T1, in T2, in T3, in T4, in T5, in T6, in T7>(scoped ref T1 refArg, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6, T7 arg7)
    where T1 : allows ref struct
    where T2 : allows ref struct
    where T3 : allows ref struct
    where T4 : allows ref struct
    where T5 : allows ref struct
    where T6 : allows ref struct
    where T7 : allows ref struct;
public delegate void RefInAction<T1, in T2, in T3, in T4, in T5, in T6, in T7, in T8>(scoped ref T1 refArg, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6, T7 arg7, T8 arg8)
    where T1 : allows ref struct
    where T2 : allows ref struct
    where T3 : allows ref struct
    where T4 : allows ref struct
    where T5 : allows ref struct
    where T6 : allows ref struct
    where T7 : allows ref struct
    where T8 : allows ref struct;