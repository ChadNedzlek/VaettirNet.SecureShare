using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Reflection;
using System.Text;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.PackedBinarySerialization.Buffers;

namespace VaettirNet.PackedBinarySerialization;

public record class PackedBinarySerializationOptions(Encoding? Encoding = null, bool UsePackedEncoding = false, bool ImplicitRepeat = false);

public class PackedBinarySerializer
{
    public PackedBinarySerializer AddSubType<TBase, TDerived>(int tag) => AddSubType(typeof(TBase), typeof(TDerived), tag);
    public PackedBinarySerializer AddSubType(Type baseClass, Type derived, int tag)
    {
        _subTypeType.Add((baseClass, tag), derived);
        _subTypeTags.Add((baseClass, derived), tag);
        return this;
    }
    
    public PackedBinarySerializer AddGenericType<T>(params int [] tags) => AddGenericType(typeof(T), tags);
    public PackedBinarySerializer AddGenericType(Type genericType, params int [] tags)
    {
        var def = genericType.GetGenericTypeDefinition();
        var p = def.GetTypeInfo().GenericTypeParameters;
        if (p.Length != tags.Length)
        {
            throw new ArgumentException(
                $"Type {genericType.FullName} has {p.Length} generic parameters, but {tags.Length} tags were provided",
                nameof(tags)
            );
        }

        Type[] gta = genericType.GetGenericArguments();
        
        for (int i = 0; i < p.Length; i++)
        {
            var tag = tags[i];
            _genericTypeArgs[(def, i, tag)] = gta[i];
            _genericTypeTags[(def, i, gta[i])] = tag;
        }

        return this;
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

    private abstract record Accessor(Type Type, string Name)
    {
        public abstract object? GetValue(object instance);
        public abstract void SetValue(object instance, object value);
    }

    private record FieldAccessor(FieldInfo Field) : Accessor(Field.FieldType, Field.Name)
    {
        public override object? GetValue(object instance) => Field.GetValue(instance);
        public override void SetValue(object instance, object value) => Field.SetValue(instance, value);
    }
    
    private record PropertyAccessor(PropertyInfo Property) : Accessor(Property.PropertyType, Property.Name)
    {
        public override object? GetValue(object instance) => Property.GetValue(instance);
        public override void SetValue(object instance, object value) => Property.SetValue(instance, value);
    }

    private record MissingAccessor() : Accessor(typeof(void), "<missing>")
    {
        public override object? GetValue(object instance) => throw new NotSupportedException();
        public override void SetValue(object instance, object value) => throw new NotSupportedException();
    }

    private readonly Dictionary<Type, IList<Accessor>> _memberAccessors = [];
    private readonly Dictionary<Type, ConstructorInfo?> _validCtor = [];

    private ConstructorInfo? GetValidPackedCtor(Type type, PackedBinarySerializableAttribute attr)
    {
        if (_validCtor.TryGetValue(type, out var valid))
            return valid;

        if (type.GetConstructors()
                .FirstOrDefault(c => c.GetCustomAttribute<PackageBinaryConstructorAttribute>() is not null) is not {} ctor)
        {
            _validCtor.Add(type, null);
            return null;
        }

        var acc = GetMemberAccessors(type, attr);
        ParameterInfo[] parameters = ctor.GetParameters();
        if (acc.Count != parameters.Length)
        {
            throw new ArgumentException($"Constructor {type.FullName} marked with [PackageBinaryConstructor] does not match member count", nameof(type));
        }

        for (int i = 0; i < acc.Count; i++)
        {
            ParameterInfo p = parameters[i];
            Accessor a = acc[i];
            if (a.Type != p.ParameterType)
            {
                throw new ArgumentException($"Constructor {type.FullName} marked with [PackageBinaryConstructor] parameter at position {i} `{p.ParameterType.Name} {p.Name}` does not match member `{a.Type} {a.Name}`", nameof(type));
            }
        }

        _validCtor.Add(type, ctor);
        return ctor;
    }

    private IList<Accessor> GetMemberAccessors(Type type, PackedBinarySerializableAttribute attr)
    {
        if (!_memberAccessors.TryGetValue(type, out var cached))
        {
            _memberAccessors.Add(type, cached = Build());
        }

        return cached;

        IList<Accessor> Build()
        {
            if (attr.SequentialMembers)
            {
                List<Accessor> values = [];
                foreach (var mem in type.GetMembers(
                        BindingFlags.Public | BindingFlags.Instance | (attr.IncludeNonPublic ? BindingFlags.NonPublic : 0)
                    ))
                {
                    if (mem.CustomAttributes.Any(c => c.AttributeType == typeof(PackedBinaryMemberIgnoreAttribute)))
                    {
                        continue;
                    }

                    switch (mem)
                    {
                        case FieldInfo f:
                        {
                            values.Add(new FieldAccessor(f));
                            break;
                        }
                        case PropertyInfo p:
                        {
                            values.Add(new PropertyAccessor(p));
                            break;
                        }
                    }
                }

                return values;
            }

            {
                int max = 0;
                Dictionary<int, Accessor> accessors = [];
                foreach (var mem in type.GetMembers(
                        BindingFlags.Public | BindingFlags.Instance | (attr.IncludeNonPublic ? BindingFlags.NonPublic : 0)
                    ))
                {
                    if (mem.GetCustomAttribute<PackedBinaryMemberAttribute>() is not { } memAttr)
                    {
                        continue;
                    }

                    switch (mem)
                    {
                        case FieldInfo f:
                        {
                            accessors.Add(memAttr.Order - 1, new FieldAccessor(f));
                            max = Math.Max(max, memAttr.Order);
                            break;
                        }
                        case PropertyInfo p:
                        {
                            accessors.Add(memAttr.Order - 1, new PropertyAccessor(p));
                            max = Math.Max(max, memAttr.Order);
                            break;
                        }
                    }
                }

                Accessor[] ret = new Accessor[max];
                for (int i = 0; i < max; i++)
                {
                    if (accessors.TryGetValue(i, out var acc))
                    {
                        ret[i] = acc;
                    }
                    else
                    {
                        ret[i] = new MissingAccessor();
                    }
                }

                return ret;
            }
        }
    }

    private Dictionary<(Type baseClass, int tag), Type?> _subTypeType = [];
    private Dictionary<(Type baseClass, Type type), int?> _subTypeTags = [];
    private Type? GetSubtypeFromTag(Type baseClass, int tag)
    {
        if (!_subTypeType.TryGetValue((baseClass, tag), out var type))
        {
            _subTypeType.Add(
                (baseClass, tag),
                type = baseClass
                    .GetCustomAttributes<PackedBinaryIncludeTypeAttribute>()
                    .FirstOrDefault(a => a.Tag == tag)
                    ?.Type
            );
        }

        return type;
    }
    
    private int? GetSubtypeTag(Type baseClass, Type type)
    {
        if (!_subTypeTags.TryGetValue((baseClass, type), out var tag))
        {
            _subTypeTags.Add(
                (baseClass, type),
                tag = baseClass
                    .GetCustomAttributes<PackedBinaryIncludeTypeAttribute>()
                    .FirstOrDefault(a => a.Type == type)
                    ?.Tag
            );
        }

        return tag;
    }

    private Dictionary<(Type baseClass, int index, int tag), Type?> _genericTypeArgs = [];
    private Dictionary<(Type baseClass, int index, Type type), int?> _genericTypeTags = [];
    private Type? GetGenericArgumentType(Type genericType, int paramIndex, int tag)
    {
        if (!_genericTypeArgs.TryGetValue((genericType, paramIndex, tag), out var type))
        {
            _genericTypeArgs.Add(
                (genericType, paramIndex, tag),
                type = genericType
                    .GetTypeInfo()
                    .GenericTypeParameters[paramIndex]
                    .GetCustomAttributes<PackedBinaryIncludeTypeAttribute>()
                    .FirstOrDefault(a => a.Tag == tag)
                    ?.Type
            );
        }

        return type;
    }

    private int? GetGenericArgumentTag(Type genericType, int paramIndex)
    {
        var paramType = genericType.GetGenericArguments()[paramIndex];
        if (!_genericTypeTags.TryGetValue((genericType, paramIndex, paramType), out var tag))
        {
            _genericTypeTags.Add(
                (genericType, paramIndex, paramType),
                tag = genericType
                    .GetGenericTypeDefinition()
                    .GetTypeInfo()
                    .GenericTypeParameters[paramIndex]
                    .GetCustomAttributes<PackedBinaryIncludeTypeAttribute>()
                    .FirstOrDefault(a => a.Type == paramType)
                    ?.Tag
            );
        }

        return tag;
    }

    private Dictionary<Type, ReadOnlyMemory<int>> _typeTags = [];

    public ReadOnlyMemory<int> GetTypeTags(Type declaredType, Type valueType)
    {
        if (_typeTags.TryGetValue(valueType, out var cached)) return cached;
        
        List<int> tags = [];
        if (declaredType != valueType)
        {
            if (GetSubtypeTag(declaredType, valueType) is not {} subTag)
            {
                throw new ArgumentException(
                    $"Type {valueType.Name} is not a declared subtype of {declaredType.Name}, use [PackedBinaryIncludeType]",
                    nameof(valueType)
                );
            }
            tags.Add(subTag);
        }

        if (valueType.IsGenericType)
        {
            int len = valueType.GetGenericArguments().Length;
            for (int i = 0; i < len; i++)
            {
                if (GetGenericArgumentTag(valueType, i) is not {} gtaTag)
                {
                    throw new ArgumentException(
                        $"Type {valueType.Name} is not a specified generic instance use [PackedBinaryIncludeType]",
                        nameof(valueType)
                    );
                }
                tags.Add(gtaTag);
            }
        }
        _typeTags.Add(valueType, cached = tags.ToArray());

        return cached;
    }
    
    public Type GetType(Type type, ReadOnlyMemory<int> tags)
    {
        if (tags.Length == 0)
            return type;

        ReadOnlySpan<int> tspan = tags.Span;
        if (GetSubtypeFromTag(type, tspan[0]) is { } subType)
        {
            return GetType(subType, tags[1..]);
        }

        if (type.IsGenericType && type.GetGenericTypeDefinition() is {} def && type == def)
        {
            var p = type.GetTypeInfo().GenericTypeParameters;
            if (tspan.Length != p.Length)
            {
                throw new ArgumentException($"Incorrect generic tag count, found {tspan.Length} but require {p.Length}");
            }

            Type[] gtas = new Type[tspan.Length];
            for (int i = 0; i < tspan.Length; i++)
            {
                Type? gta = GetGenericArgumentType(def, i, tspan[i]);
                if (gta is null)
                {
                    throw new ArgumentException("Unable to find target type");
                }

                gtas[i] = gta;
            }

            return def.MakeGenericType(gtas);
        }
        
        throw new ArgumentException("Unable to find target type");
    }
}