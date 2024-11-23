using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryWriter<TWriter>
{
    private bool TryWriteWithMetadata<T>(T? value, PackedBinarySerializationContext ctx, out int written)
    {
        if (ctx.TagMap != null && !typeof(T).IsValueType)
        {
            written = WriteMemberWithMetadataCore(value, ctx);
            return true;
        }

        if (typeof(T).GetCustomAttribute<PackedBinarySerializableAttribute>() is not null)
        {
            written = WriteWithMetadataCore(value, ctx);
            return true;
        }

        if (_serializer.GetSubtypeTags(typeof(T)) is not null || _serializer.GetEffectiveSerializableAttribute(typeof(T)) is not null)
        {
            written = WriteWithMetadataCore(value, ctx);
            return true;
        }

        written = 0;
        return false;
    }

    public int WriteWithMetadata<T>(T value, PackedBinarySerializationContext ctx) =>
        TryWriteWithMetadata(value, ctx, out int written) ? written : throw new ArgumentException($"Type {typeof(T).Name} is not metadata writable");

    private delegate int WriteMetadataDelegate<in T>(ref PackedBinaryWriter<TWriter> writer, T? value, PackedBinarySerializationContext ctx);
    private delegate int WriteTagDelegate(ref PackedBinaryWriter<TWriter> writer, object? value, PackedBinarySerializationContext ctx);
    
    private int WriteWithMetadataCore<T>(T? value, PackedBinarySerializationContext ctx)
    {
        return GetMetadataWriteDelegate<T>(typeof(T)).Invoke(ref this, value, ctx);
    }

    private static Func<TObj, TMember>? GetMemberAccess<TObj, TMember>(MemberInfo member)
    {
        return member switch
        {
            FieldInfo f => BuildFieldGetter(f),
            PropertyInfo p => p.GetGetMethod(true)!.CreateDelegate<Func<TObj, TMember>>(),
            _ => null,
        };

        Func<TObj, TMember> BuildFieldGetter(FieldInfo fieldInfo)
        {
            DynamicMethod getter = new($"{typeof(TObj).Name}_Get_{fieldInfo.Name}", typeof(TMember), [typeof(TObj)]);
            ILGenerator il = getter.GetILGenerator();
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldfld, fieldInfo);
            il.Emit(OpCodes.Ret);
            return getter.CreateDelegate<Func<TObj, TMember>>();
        }
    }

    private static void WriteMemberStatic<TObj, TMember>(
        ref PackedBinaryWriter<TWriter> writer,
        TObj value,
        Delegate writeCallback,
        PackedBinarySerializationContext ctx,
        ref int written
    )
    {
        Func<TObj, TMember> typedCallback = (Func<TObj, TMember>)writeCallback;
        written += writer.Write(typedCallback(value), ctx);
    }

    private delegate void WriteMemberStaticDelegate<in TObj>(
        ref PackedBinaryWriter<TWriter> writer,
        TObj value,
        PackedBinarySerializationContext ctx,
        ref int written
    );
    
    private delegate void WriteMemberStaticCallbackDelegate<in TObj>(
        ref PackedBinaryWriter<TWriter> writer,
        TObj value,
        Delegate getter,
        PackedBinarySerializationContext ctx,
        ref int written
    );

    private delegate WriteMemberStaticDelegate<TObj> BuildMemberWriterMethod<in TObj>(MemberInfo member);
    private static WriteMemberStaticDelegate<TObj>? BuildWriteMember<TObj>(scoped ref PackedBinaryWriter<TWriter> writer, MemberInfo member)
    {
        if (ReflectionHelpers.GetMemberType(member) is not { } memberType)
        {
            return null;
        }

        if (typeof(TObj).IsValueType)
        {
            MethodInfo method = typeof(PackedBinaryWriter<TWriter>).GetMethod(
                nameof(BuildValueTypeWriteMemberTyped),
                BindingFlags.Static | BindingFlags.NonPublic
            )!;
            return method.MakeGenericMethod(typeof(TObj), memberType)
                .CreateDelegate<BuildMemberWriterMethod<TObj>>()
                .Invoke(member);
        }

        {
            MethodInfo method = typeof(PackedBinaryWriter<TWriter>).GetMethod(
                nameof(BuildRefTypeWriteMemberTyped),
                BindingFlags.Static | BindingFlags.NonPublic
            )!;
            return method.MakeGenericMethod(typeof(TObj), member.DeclaringType!, memberType)
                .CreateDelegate<BuildMemberWriterMethod<TObj>>()
                .Invoke(member);
        }
    }

    private static WriteMemberStaticDelegate<TType>? BuildValueTypeWriteMemberTyped<TType, TMember>(MemberInfo member)
    {
        Func<TType, TMember>? access = GetMemberAccess<TType, TMember>(member);
        if (access == null)
            return null;

        (var makeIt, Func<PackedBinarySerializationContext, PackedBinarySerializationContext> newContext) =
            BuildMemberWriteDelegate<TType, TMember>(member);

        return WriteMember;

        void WriteMember(ref PackedBinaryWriter<TWriter> writer, TType value, PackedBinarySerializationContext ctx, ref int written)
        {
            makeIt(ref writer, value, access, newContext(ctx), ref written);
        }
    }

    private static WriteMemberStaticDelegate<TObj>? BuildRefTypeWriteMemberTyped<TObj, TMemberDecl, TMember>(MemberInfo member)
        where TObj : notnull
        where TMemberDecl : class
    {
        Func<TMemberDecl, TMember>? onDecl = GetMemberAccess<TMemberDecl, TMember>(member);
        if (onDecl == null)
            return null;

        Func<TObj, TMember> access;
        if (typeof(TObj) == typeof(TMemberDecl))
        {
            access = Unsafe.As<Func<TObj, TMember>>(onDecl);
        }
        else
        {
            access = o => onDecl(Unsafe.As<TMemberDecl>(o));
        }

        (var makeIt, Func<PackedBinarySerializationContext, PackedBinarySerializationContext> newContext) =
            BuildMemberWriteDelegate<TObj, TMember>(member);

        return WriteMember;

        void WriteMember(ref PackedBinaryWriter<TWriter> writer, TObj value, PackedBinarySerializationContext ctx, ref int written)
        {
            makeIt(ref writer, value, access, newContext(ctx), ref written);
        }
    }

    private static (WriteMemberStaticCallbackDelegate<TDerivedType> makeIt, Func<PackedBinarySerializationContext, PackedBinarySerializationContext>
        newContext) BuildMemberWriteDelegate<TDerivedType, TMember>(MemberInfo member)
    {
        MethodInfo? method = typeof(PackedBinaryWriter<TWriter>).GetMethod(nameof(WriteMemberStatic), BindingFlags.Static | BindingFlags.NonPublic);
        WriteMemberStaticCallbackDelegate<TDerivedType> makeIt = method!.MakeGenericMethod(typeof(TDerivedType), typeof(TMember))
            .CreateDelegate<WriteMemberStaticCallbackDelegate<TDerivedType>>();

        Func<PackedBinarySerializationContext, PackedBinarySerializationContext> newContext = ctx => ctx.Descend();

        var typeIncludes = member.GetCustomAttributes<PackedBinaryIncludeTypeAttribute>().ToList();
        if (typeIncludes.Count != 0)
        {

            TagMap ctxTags = new();
            ctxTags.Add(typeof(TMember), 0);
            foreach (var attr in typeIncludes)
            {
                ctxTags.Add(attr.Type, attr.Tag);
            }

            newContext = ctx => ctx.Descend() with { TagMap = ctxTags };
        }

        return (makeIt, newContext);
    }

    private static readonly ConditionalWeakTable<PackedBinarySerializer, CachedSerializerDelegate<PackedBinaryWriter<TWriter>, Type, Delegate>> s_dynamicWriters = new();

    private WriteMetadataDelegate<T> GetMetadataWriteDelegate<T>(Type type)
    {
        if (s_dynamicWriters.TryGetValue(_serializer, out var cache) && cache.SerializerRevision == _serializer.MetadataRevision)
        {
            return (WriteMetadataDelegate<T>)cache.Delegates.GetOrCreate(ref this, type, Build);
        }
            
        // Either the revision didn't match (meaning we need to recalculate the delegates) or it wasn't present yet
        s_dynamicWriters.AddOrUpdate(_serializer, cache = new CachedSerializerDelegate<PackedBinaryWriter<TWriter>, Type, Delegate>(_serializer.MetadataRevision));
        return (WriteMetadataDelegate<T>)cache.Delegates.GetOrCreate(ref this, type, Build);

        WriteMetadataDelegate<T> Build(Type type, scoped ref PackedBinaryWriter<TWriter> writer)
        {
            if (!type.IsAssignableTo(typeof(T)))
            {
                throw new ArgumentException($"Type {type.Name} is not assignable to {typeof(T).Name}");
            }

            if (writer._serializer.GetSubtypeTags(type) is { Count: > 0 } dynamicTags)
            {
                // We need to use the table to get things, since this serializer has changed stuff.
                return writer.GetDynamicWriteDelegate<T>(type, dynamicTags);
            }

            // The serializer has no dynamic tagged types registered for this type, so we can just use the static one
            return writer.GetStaticWriteDelegate<T>(type);
        }
    }

    private WriteMetadataDelegate<T> GetStaticWriteDelegate<T>(Type type)
    {
        var tag = GetStaticWriteTagDelegate(type);
        return (ref PackedBinaryWriter<TWriter> writer, T? value, PackedBinarySerializationContext ctx) =>
        {
            int written = tag(ref writer, value, ctx);

            if (value is null)
                return written;

            return written + writer.GetStaticWriteMembersDelegate<T>(value.GetType()).Invoke(ref writer, value, ctx);
        };
    }

    private WriteMetadataDelegate<T> GetDynamicWriteDelegate<T>(Type type, Dictionary<Type, int> dynamicTags)
    {
        var tag = GetDynamicWriteTagDelegate(type, dynamicTags);
        return (ref PackedBinaryWriter<TWriter> writer, T? value, PackedBinarySerializationContext ctx) =>
        {
            int written = tag(ref writer, value, ctx);

            if (value is null)
                return written;

            return written + writer.GetDynamicWriteMembersDelegate<T>(value.GetType()).Invoke(ref writer, value, ctx);
        };
    }

    private int WriteMemberWithMetadataCore(object? value, PackedBinarySerializationContext ctx)
    {
        if (value is null)
        {
            return WriteInt32(-1, ctx with { UsePackedIntegers = true });
        }

        if (!TryWriteContextTag(value, ctx, out int written))
        {
            throw new ArgumentException($"Value of type {value.GetType().Name} not allowed in this context", nameof(value));
        }

        return written + GetDynamicWriteMembersDelegate<object>(value.GetType()).Invoke(ref this, value, ctx);
    }

    private static readonly DelegateCache<PackedBinaryWriter<TWriter>, Type, WriteTagDelegate> s_staticTagDelegates = new();

    private delegate Dictionary<Type, T>? GetSupplementalTypeInformation<T>(ref PackedBinaryWriter<TWriter> writer, Type type);
    private delegate TOut ProcessSupplementalTypeInformation<in TIn, out TOut>(ref PackedBinaryWriter<TWriter> writer, Type type, TIn value);
    private delegate TOut ProcessAttributeTypeInformation<out TOut>(ref PackedBinaryWriter<TWriter> writer, Type type, PackedBinaryIncludeTypeAttribute value);
    
    private Dictionary<Type, T> MakeTypeClosure<T, TSupplemental>(
        Type root,
        T valueForRoot,
        ProcessAttributeTypeInformation<T> fromAttribute,
        GetSupplementalTypeInformation<TSupplemental>? supplemental,
        ProcessSupplementalTypeInformation<TSupplemental, T>? fromSupplemental
    )
    {
        Dictionary<Type, T> value = [];
        value.Add(root, valueForRoot);
        Queue<Type> scanning = [];
        scanning.Enqueue(root);
        while (scanning.TryDequeue(out var t))
        {
            foreach (var attr in t.GetCustomAttributes<PackedBinaryIncludeTypeAttribute>())
            {
                value.Add(attr.Type, fromAttribute(ref this, t, attr));
                scanning.Enqueue(attr.Type);
            }

            if (supplemental is not null && fromSupplemental is not null)
            {
                foreach ((Type key, TSupplemental sup) in supplemental(ref this, t) ?? [])
                {
                    value.Add(key, fromSupplemental(ref this, key, sup));
                    scanning.Enqueue(key);
                }
            }
        }

        return value;
    }

    private WriteTagDelegate GetStaticWriteTagDelegate(Type type)
    {
        return s_staticTagDelegates.GetOrCreate(ref this, type, Build);

        static WriteTagDelegate Build(Type type, scoped ref PackedBinaryWriter<TWriter> writer)
        {
            if (type.IsValueType)
                return (ref PackedBinaryWriter<TWriter> _, object? _, PackedBinarySerializationContext _) => 0;

            Dictionary<Type, int> tags = writer.MakeTypeClosure(
                type,
                0,
                (ref PackedBinaryWriter<TWriter> _, Type _, PackedBinaryIncludeTypeAttribute attr) => attr.Tag,
                (ref PackedBinaryWriter<TWriter> w, Type t) => w._serializer.GetSubtypeTags(t),
                (ref PackedBinaryWriter<TWriter> _, Type _, int tag) => tag
            );
            
            if (tags.GroupBy(a => a.Value).FirstOrDefault(x => x.Count() > 1) is {} collision)
            {
                throw new ArgumentException(
                    $"When serializing {type.Name}, found conflicting tag {collision.Key} for types {string.Join(", ", collision.Select(c => c.Key.Name))}"
                );
            }

            return (ref PackedBinaryWriter<TWriter> writer, object? value, PackedBinarySerializationContext ctx) =>
            {
                if (value is null)
                    return writer.WriteInt32(-1, ctx with { UsePackedIntegers = true });

                if (tags.TryGetValue(value.GetType(), out var tag))
                {
                    return writer.WriteInt32(tag, ctx with { UsePackedIntegers = true });
                }

                return 0;
            };
        }
    }

    private bool TryWriteContextTag(object value, PackedBinarySerializationContext ctx, out int written)
    {
        if (ctx.TagMap?.TryGetTag(value.GetType(), out int tag) is true)
        {
            written = WriteInt32(tag, ctx with { UsePackedIntegers = true });
            return true;
        }

        written = 0;
        return false;
    }

    private WriteTagDelegate GetDynamicWriteTagDelegate(Type type, Dictionary<Type, int> dynamicTags)
    {
        WriteTagDelegate staticDelegate = GetStaticWriteTagDelegate(type);
        
        return (ref PackedBinaryWriter<TWriter> writer, object? value, PackedBinarySerializationContext ctx) =>
        {
            if (value is null)
            {
                return writer.WriteInt32(-1, ctx with { UsePackedIntegers = true });
            }

            if (writer.TryWriteContextTag(value, ctx, out int written))
            {
                return written;
            }

            if (dynamicTags.TryGetValue(value.GetType(), out var tag))
            {
                return writer.WriteInt32(tag, ctx with { UsePackedIntegers = true });
            }

            return staticDelegate(ref writer, value, ctx);
        };
    }

    private static readonly DelegateCache<PackedBinaryWriter<TWriter>, (Type baseType, Type derivedType), Delegate> s_staticMemberWriteCache = new();

    private WriteMetadataDelegate<T> GetStaticWriteMembersDelegate<T>(Type valueType)
    {
        return (WriteMetadataDelegate<T>)s_staticMemberWriteCache.GetOrCreate(ref this, (typeof(T), valueType), Build);
        
        static Delegate Build((Type baseType, Type derivedType) key, ref PackedBinaryWriter<TWriter> writer)
        {
            WriteMemberStaticDelegate<T>? build = null;
            
            if (!key.derivedType.IsAssignableTo(typeof(T)))
            {
                throw new ArgumentException($"Type {key.derivedType.Name} is not assignable to {typeof(T).Name}", nameof(valueType));
            }

            PackedBinarySerializableAttribute attr = key.derivedType.GetCustomAttribute<PackedBinarySerializableAttribute>() ??
                writer._serializer.GetEffectiveSerializableAttribute(key.derivedType);

            var targetMembers = key.derivedType.GetMembers(
                    BindingFlags.Instance | BindingFlags.Public | (attr?.IncludeNonPublic is true? BindingFlags.NonPublic : 0)
                )
                .Where(a => a.GetCustomAttribute<PackedBinaryMemberIgnoreAttribute>() is null);
            if (!attr.SequentialMembers)
            {
                targetMembers = targetMembers
                    .Select(member => (member, attr: member.GetCustomAttribute<PackedBinaryMemberAttribute>()))
                    .Where(x => x.attr is not null)
                    .OrderBy(x => x.attr!.Order)
                    .Select(x => x.member);
            }

            foreach (MemberInfo member in targetMembers)
            {
                if (BuildWriteMember<T>(ref writer, member) is { } callback)
                {
                    build += callback;
                }
            }

            return (WriteMetadataDelegate<T>)delegate(ref PackedBinaryWriter<TWriter> writer, T value, PackedBinarySerializationContext ctx)
            {
                int written = 0;
                build?.Invoke(ref writer, value, ctx, ref written);
                return written;
            }!;
        }
    }

    private WriteMetadataDelegate<T> GetDynamicWriteMembersDelegate<T>(Type valueType)
    {
        // TODO: Do we let the serializer completely define an entire type, members and all?
        return GetStaticWriteMembersDelegate<T>(valueType);
    }
}