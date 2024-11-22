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

    private T? ReadFromMetadataAsType<T>(PackedBinarySerializationContext ctx)
    {
        if (typeof(T).IsValueType)
        {
#nullable disable
            return ReadMembers<T>(typeof(T), ctx);
#nullable restore
        }

        int tag = ReadInt32(ctx with { UsePackedIntegers = true });
        if (tag == -1)
            return default;

        Type? instanceType = null;
        if (tag == 0)
        {
            instanceType = typeof(T);
        }
        else if (ctx.TagMap is { } ctxMap && ctxMap.TryGetType(tag, out Type? ctxType))
        {
            instanceType = ctxType;
        }
        else if (_serializer.GetTagSubtypes(typeof(T)) is { } sMap && sMap.TryGetValue(tag, out Type? sType))
        {
            instanceType = sType;
        }
        else
        {
            foreach (var attr in typeof(T).GetCustomAttributes<PackedBinaryIncludeTypeAttribute>())
            {
                if (attr.Tag == tag)
                {
                    instanceType = attr.Type;
                    break;
                }
            }
        }

        if (instanceType is null)
        {
            throw new ArgumentException($"Unable to transform tag {tag} while reading type {typeof(T).Name}");
        }

#nullable disable
        return ReadMembers<T>(instanceType, ctx);
#nullable restore
    }

    private static TBase Construct<TBase, TDerived>() where TDerived : TBase
    {
        return Activator.CreateInstance<TDerived>();
    }

    private T ReadMembers<T>(Type targetType, PackedBinarySerializationContext ctx)
        where T : notnull
    {
        Func<T> create = GetMember<Func<T>>(nameof(Construct), typeof(T), targetType);
        T instance = create();
        PopulateMembers(targetType, instance, ctx);
        return instance;
    }

    private void PopulateMembers<T>(Type targetType, T instance, PackedBinarySerializationContext ctx)
        where T : notnull
    {
        if (!targetType.IsAssignableTo(typeof(T)))
        {
            throw new ArgumentException($"Type {targetType.Name} is not assignable to {typeof(T).Name}", nameof(targetType));
        }

        var attr = targetType.GetCustomAttribute<PackedBinarySerializableAttribute>()!;

        IEnumerable<MemberInfo> targetMembers = targetType.GetMembers(
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

        WriteMembers(instance, targetMembers, ctx);
    }

    private void WriteMembers<TIn>(TIn instance, IEnumerable<MemberInfo> members, PackedBinarySerializationContext ctx)
     where TIn : notnull
    {
        foreach (var member in members)
        {
            Type? memberType = ReflectionHelpers.GetMemberType(member);
            if (memberType != null)
            {
                var setter = GetMember<WriteMemberDelegate<TIn>>(nameof(WriteMemberTypeCast), instance.GetType(), typeof(TIn), memberType);
                setter(ref this, instance, member, ctx);
            }
        }
    }

    private delegate void WriteMemberDelegate<in TIn>(
        scoped ref PackedBinaryReader<TReader> reader,
        TIn instance,
        MemberInfo member,
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