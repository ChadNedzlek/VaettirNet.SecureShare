using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryReader<TReader>
{
    public bool TryReadFromMetadata<T>(Type type, PackedBinarySerializationContext ctx, out T? value)
    {
        if (ctx.TagMap is not null)
        {
        }

        if (type.GetCustomAttribute<PackedBinarySerializableAttribute>() is { } attr)
        {
            object? o = ReadFromMetadataCore<object>(type, ctx);
            if (o is null)
            {
                value = default;
            }
            else
            {
                ref T refT = ref Unsafe.As<object, T>(ref o);
                value = refT;
            }

            return true;
        }

        value = default;
        return false;
    }

    public T? ReadFromMetadata<T>(PackedBinarySerializationContext ctx) => TryReadFromMetadata<T>(typeof(T), ctx, out var value)
        ? value
        : throw new ArgumentException($"Type {typeof(T).Name} is not metadata readable");

    private static Action<TObj, TMember>? GetMemberAccess<TObj, TMember>(MemberInfo member)
    {
        return member switch
        {
            FieldInfo f => BuildFieldSetter(f),
            PropertyInfo p => p.GetSetMethod(true)!.CreateDelegate<Action<TObj, TMember>>(),
            _ => null,
        };

        Action<TObj, TMember> BuildFieldSetter(FieldInfo fieldInfo)
        {
            DynamicMethod getter = new($"{typeof(TObj).Name}_Set_{fieldInfo.Name}", typeof(void), [typeof(TObj), typeof(TMember)]);
            ILGenerator il = getter.GetILGenerator();
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldarg_1);
            il.Emit(OpCodes.Stfld, fieldInfo);
            il.Emit(OpCodes.Ret);
            return getter.CreateDelegate<Action<TObj, TMember>>();
        }
    }

    private T? ReadFromMetadataCore<T>(Type returnType, PackedBinarySerializationContext ctx)
    {
        return GetMember<ReadFromMetadataCoreStaticDelegate<T>>(nameof(ReadFromMetadataCoreStaticTypeCast), returnType, typeof(T))
            .Invoke(ref this, ctx);
    }

    private delegate T? ReadFromMetadataCoreStaticDelegate<out T>(scoped ref PackedBinaryReader<TReader> reader, PackedBinarySerializationContext ctx);

    private static TOut? ReadFromMetadataCoreStaticTypeCast<TIn, TOut>(scoped ref PackedBinaryReader<TReader> reader, PackedBinarySerializationContext ctx)
    {
        TIn? value = reader.ReadFromMetadataAsType<TIn>(ctx);
        if (value is null)
        {
            return default;
        }

        ref TOut refT = ref Unsafe.As<TIn, TOut>(ref value);
        return refT;
    }


    private static readonly DelegateCache<PackedBinaryReader<TReader>, Type, ReadTypeCallback> s_tagDelegates = new();
    
    private delegate Type? ReadTypeCallback(scoped ref PackedBinaryReader<TReader> reader);
    
    private T? ReadFromMetadataAsType<T>(PackedBinarySerializationContext ctx)
    {
        ReadTypeCallback callback = s_tagDelegates.GetOrCreate(ref this, typeof(T), CreateCallback);
        Type? instanceType = callback(ref this);

        if (instanceType is null)
        {
            return default;
        }

#nullable disable
        return ReadMembers<T>(instanceType, ctx);
#nullable restore
        ReadTypeCallback CreateCallback(Type key, ref PackedBinaryReader<TReader> refType)
        {
            Dictionary<int, Type> tagToType = key.GetCustomAttributes<PackedBinaryIncludeTypeAttribute>().ToDictionary(a => a.Tag, a => a.Type);
            return GetTypeFromTag;
            
            Type? GetTypeFromTag(scoped ref PackedBinaryReader<TReader> reader)
            {
                if (key.IsValueType)
                {
#nullable disable
                    return key;
#nullable restore
                }

                int tag = reader.ReadInt32(ctx with { UsePackedIntegers = true });
                if (tag == -1)
                    return null;

                Type? type = null;
                if (tag == 0)
                {
                    type = key;
                }
                else if (ctx.TagMap is { } ctxMap && ctxMap.TryGetType(tag, out Type? ctxType))
                {
                    type = ctxType;
                }
                else if (reader._serializer.GetTagSubtypes(key) is { } sMap && sMap.TryGetValue(tag, out Type? sType))
                {
                    type = sType;
                }
                else if (tagToType.TryGetValue(tag, out Type? aType))
                {
                    type = aType;
                }

                if (type is null)
                {
                    throw new ArgumentException($"Unable to transform tag {tag} while reading type {typeof(T).Name}");
                }

                return type;
            }
        }
    }

    private static TBase Construct<TBase, TDerived>() where TDerived : TBase
    {
        return Activator.CreateInstance<TDerived>();
    }

    private static readonly DelegateCache<PackedBinaryReader<TReader>, (Type baseType, Type derivedType), Delegate> s_constructCache = new();
    
    private T ReadMembers<T>(Type targetType, PackedBinarySerializationContext ctx)
        where T : notnull
    {
        var create = (Func<T>)s_constructCache.GetOrCreate(
                ref this,
                (typeof(T), targetType),
                ((Type baseType, Type derivedType) types, ref PackedBinaryReader<TReader> r) =>
                    GetMember<Func<T>>(nameof(Construct), types.baseType, types.derivedType)
            );
        T instance = create();
        PopulateMembers(targetType, instance, ctx);
        return instance;
    }

    private static readonly DelegateCache<PackedBinaryReader<TReader>, (Type returnType, Type targetType, Type instanceType), Delegate> s_writeMembersCache = new();
    
    private void PopulateMembers<T>(Type targetType, T instance, PackedBinarySerializationContext ctx)
        where T : notnull
    {
        if (!targetType.IsAssignableTo(typeof(T)))
        {
            throw new ArgumentException($"Type {targetType.Name} is not assignable to {typeof(T).Name}", nameof(targetType));
        }

        var combinedSetters = (WriteAllMembersDelegate<T>)s_writeMembersCache.GetOrCreate(ref this, (typeof(T), targetType, instance.GetType()), BuildWriterDelegate);
        combinedSetters(ref this, instance, ctx);

        return;

        static Delegate BuildWriterDelegate((Type returnType, Type targetType, Type instanceType) key, ref PackedBinaryReader<TReader> refType)
        {
            var attr = key.targetType.GetCustomAttribute<PackedBinarySerializableAttribute>()!;

            IEnumerable<MemberInfo> targetMembers = key.targetType.GetMembers(
                    BindingFlags.Instance | BindingFlags.Public | (attr.IncludeNonPublic ? BindingFlags.NonPublic : 0)
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

            WriteAllMembersDelegate<T> writeAllMembersDelegate = null;
            foreach (var member in targetMembers)
            {
                Type? memberType = ReflectionHelpers.GetMemberType(member);
                if (memberType != null)
                {
                    WriteMemberDelegate<T> setter = GetMember<WriteMemberDelegate<T>>(nameof(WriteMemberTypeCast), key.instanceType, key.returnType, memberType);
                    writeAllMembersDelegate += (scoped ref PackedBinaryReader<TReader> r, T i, PackedBinarySerializationContext c) =>
                    {
                        setter(ref r, i, member, c);
                    };
                }
            }

            return writeAllMembersDelegate ?? delegate {  };
        }
    }

    private delegate void WriteMemberDelegate<in TIn>(
        scoped ref PackedBinaryReader<TReader> reader,
        TIn instance,
        MemberInfo member,
        PackedBinarySerializationContext ctx
    );

    private delegate void WriteAllMembersDelegate<in TIn>(
        scoped ref PackedBinaryReader<TReader> reader,
        TIn instance,
        PackedBinarySerializationContext ctx
    );

    private static void WriteMemberTypeCast<TInstance, TBase, TMember>(
        scoped ref PackedBinaryReader<TReader> reader,
        TBase instance,
        MemberInfo member,
        PackedBinarySerializationContext ctx
    )
    {
        ref TInstance cast = ref Unsafe.As<TBase, TInstance>(ref instance);
        WriteMember<TInstance, TMember>(ref reader, cast, member, ctx);
    }

    private static void WriteMember<TIn, TMember>(
        scoped ref PackedBinaryReader<TReader> reader,
        TIn instance,
        MemberInfo member,
        PackedBinarySerializationContext ctx
    )
    {
        Func<MemberInfo, Action<TIn, TMember>> getSetter = GetMember<Func<MemberInfo, Action<TIn, TMember>>>(nameof(GetMemberAccess), typeof(TIn), typeof(TMember));
        Action<TIn, TMember> setter = getSetter(member);
        setter(instance, reader.Read<TMember>(ctx));
    }

    private static TDelegate GetMember<TDelegate>(string name, params Type[] gtas)
        where TDelegate : Delegate
    {
        var d = typeof(TDelegate);
        MethodInfo methodInfo = typeof(PackedBinaryReader<TReader>).GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic)!;
        MethodInfo genericInstance = methodInfo.MakeGenericMethod(gtas);
        return genericInstance.CreateDelegate<TDelegate>();
    }
}