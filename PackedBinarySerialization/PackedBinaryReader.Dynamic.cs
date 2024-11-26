using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryReader<TReader>
{
    public bool TryReadFromMetadata<T>(Type type, PackedBinarySerializationContext ctx, out T? value)
    {
        if (type.GetCustomAttribute<PackedBinarySerializableAttribute>() is not null ||
            _serializer.GetTagSubtypes(type) is not null ||
            ctx.TagMap is not null)
            return SerializeObject(ref this, out value);

        value = default;
        return false;

        bool SerializeObject(scoped ref PackedBinaryReader<TReader> reader, out T? value)
        {
            object? o = reader.ReadFromMetadataCore<object>(type, ctx);
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
    }

    public T? ReadFromMetadata<T>(PackedBinarySerializationContext ctx)
    {
        return TryReadFromMetadata(typeof(T), ctx, out T? value)
            ? value
            : throw new ArgumentException($"Type {typeof(T).Name} is not metadata readable");
    }

    private static Action<TObj, TMember>? GetMemberAccess<TObj, TMember>(MemberInfo member)
    {
        return member switch
        {
            FieldInfo f => BuildFieldSetter(f),
            PropertyInfo p =>
                // Re-lookup the value because private members are only available on the declaring type, not any derived types
                p.DeclaringType!.GetProperty(p.Name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!.GetSetMethod(true)!
                    .CreateDelegate<Action<TObj, TMember>>(),
            _ => null
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

    private delegate T? ReadFromMetadataCoreStaticDelegate<out T>(
        scoped ref PackedBinaryReader<TReader> reader,
        PackedBinarySerializationContext ctx
    );

    private static TOut? ReadFromMetadataCoreStaticTypeCast<TIn, TOut>(
        scoped ref PackedBinaryReader<TReader> reader,
        PackedBinarySerializationContext ctx
    )
    {
        TIn? value = reader.ReadFromMetadataAsType<TIn>(ctx);
        if (value is null) return default;

        ref TOut refT = ref Unsafe.As<TIn, TOut>(ref value);
        return refT;
    }


    private static readonly DelegateCache<PackedBinaryReader<TReader>, Type, ReadTypeCallback> s_tagDelegates = new();

    private delegate Type? ReadTypeCallback(scoped ref PackedBinaryReader<TReader> reader);

    private T? ReadFromMetadataAsType<T>(PackedBinarySerializationContext ctx)
    {
        ReadTypeCallback callback = s_tagDelegates.GetOrCreate(ref this, typeof(T), CreateCallback);
        Type? instanceType = callback(ref this);

        if (instanceType is null) return default;

#nullable disable
        return CreateDynamicObject<T>(instanceType, ctx);
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
                    type = key;
                else if (ctx.TagMap is { } ctxMap && ctxMap.TryGetType(tag, out Type? ctxType))
                    type = ctxType;
                else if (reader._serializer.GetTagSubtypes(key) is { } sMap && sMap.TryGetValue(tag, out Type? sType))
                    type = sType;
                else if (tagToType.TryGetValue(tag, out Type? aType)) type = aType;

                if (type is null) throw new ArgumentException($"Unable to transform tag {tag} while reading type {typeof(T).Name}");

                return type;
            }
        }
    }

    private static TBase Construct<TBase, TDerived>(scoped ref PackedBinaryReader<TReader> reader, PackedBinarySerializationContext ctx)
        where TDerived : TBase
    {
        try
        {
            return Activator.CreateInstance<TDerived>();
        }
        catch (MissingMethodException)
        {
            return (TBase)RuntimeHelpers.GetUninitializedObject(typeof(TDerived));
        }
    }

    private static readonly DelegateCache<PackedBinaryReader<TReader>, (Type baseType, Type derivedType), Delegate> s_readyDynamicCache = new();
    private static readonly DelegateCache<PackedBinaryReader<TReader>, (Type baseType, Type derivedType), Delegate> s_constructCache = new();

    private T CreateDynamicObject<T>(Type targetType, PackedBinarySerializationContext ctx)
        where T : notnull
    {
        var callback = (RefInFunc<PackedBinaryReader<TReader>, PackedBinarySerializationContext, T>)s_readyDynamicCache.GetOrCreate(
            ref this,
            (typeof(T), targetType),
            BuildCreateCallback
        );

        return callback(ref this, ctx);

        RefInFunc<PackedBinaryReader<TReader>, PackedBinarySerializationContext, T> BuildCreateCallback(
            (Type baseType, Type derivedType) key,
            scoped ref PackedBinaryReader<TReader> reader
        )
        {
            var refCtor = key.derivedType
                .GetConstructors(BindingFlags.Instance | BindingFlags.Public)
                .Select(c => (ctor: c, attr: c.GetCustomAttribute<PackedBinaryConstructorAttribute>()))
                .FirstOrDefault(c => c.attr is not null)
                .ctor;

            RefInFunc<PackedBinaryReader<TReader>, PackedBinarySerializationContext, T> create;
            List<MemberInfo> inCtor = [];
            if (refCtor is not null)
            {
                create = BuildCreateMethod(ref reader, key.baseType, key.derivedType, refCtor, out inCtor);
            }
            else
            {
                create = (RefInFunc<PackedBinaryReader<TReader>, PackedBinarySerializationContext, T>)s_constructCache.GetOrCreate(
                    ref reader,
                    (typeof(T), targetType),
                    ((Type baseType, Type derivedType) types, ref PackedBinaryReader<TReader> _) =>
                        GetMember<RefInFunc<PackedBinaryReader<TReader>, PackedBinarySerializationContext, T>>(nameof(Construct), types.baseType, types.derivedType)
                );
            }

            return (scoped ref PackedBinaryReader<TReader> reader, PackedBinarySerializationContext ctx) =>
            {
                T instance = create(ref reader, ctx);
                reader.PopulateMembers(targetType, instance, inCtor, ctx);
                return instance;
            };

            RefInFunc<PackedBinaryReader<TReader>, PackedBinarySerializationContext, T> BuildCreateMethod(
                scoped ref PackedBinaryReader<TReader> reader,
                Type returnAs,
                Type targetType,
                ConstructorInfo constructorInfo,
                out List<MemberInfo> inCtor
            )
            {
                var attr = reader.GetEffectiveTypeAttribute(targetType);
                IEnumerable<MemberInfo> targetMembers = targetType!.GetMembers(
                        BindingFlags.Instance | BindingFlags.Public | (attr.IncludeNonPublic ? BindingFlags.NonPublic : 0)
                    )
                    .Where(a => a.GetCustomAttribute<PackedBinaryMemberIgnoreAttribute>() is null);
                
                if (!attr.SequentialMembers)
                    targetMembers = targetMembers
                        .Select(member => (member, attr: member.GetCustomAttribute<PackedBinaryMemberAttribute>()))
                        .Where(x => x.attr is not null)
                        .OrderBy(x => x.attr!.Order)
                        .Select(x => x.member);

                IEnumerable<(MemberInfo member, Type type, int index)> typedMembers = targetMembers
                    .Select(m => (member: m, type: ReflectionHelpers.GetMemberType(m)))
                    .Where(m => m.type is not null)
                    .Select((m, i) => (m.member, m.type, i))
                    .ToList()!;

                int maxMemberIndex = 0;
                MemberInfo? lastMember = null;
                List<(MemberInfo member, Type type, ParameterInfo parameter, int serializedIndex)> ctorMembers = [];

                foreach (var parameter in constructorInfo.GetParameters())
                {
                    var matched = typedMembers.Where(m => MemberNameComparer.Default.Equals(m.member.Name, parameter.Name) && m.type.IsAssignableTo(parameter.ParameterType)).ToList();
                    (MemberInfo member, Type type, int index) = matched switch
                    {
                        [] => throw new ArgumentException($"Parameter {parameter.Name} does not match any serializable fields"),
                        [var m] => m,
                        [var a, var b, ..] => throw new ArgumentException($"Parameter {parameter.Name} matches multiple serializable fields: {a.member.Name} and {b.member.Name}"),
                    };

                    if (index > maxMemberIndex)
                    {
                        maxMemberIndex = index;
                        lastMember = member;
                    }

                    ctorMembers.Add((member, type, parameter, index));
                }

                foreach (var serializedMembers in typedMembers)
                {
                    if (serializedMembers.index < maxMemberIndex && ctorMembers.All(p => p.member != serializedMembers.member))
                    {
                        throw new ArgumentException(
                            $"In type {targetType.Name}, {serializedMembers.member.Name} is not a constructor parameter, but has an earlier order than {lastMember!.Name}, which is a constructor parameter. Either add {serializedMembers.member.Name} as a parameter to the constructor, or remove {lastMember!.Name}"
                        );
                    }
                }

                var serializedOrder = ctorMembers.OrderBy(m => m.serializedIndex).ToList();
                var parameterOrder = ctorMembers.OrderBy(m => m.parameter.Position);

                DynamicMethod callCtor = new(
                    $"Construct_{targetType.Name}_As_{returnAs.Name}",
                    returnAs,
                    [typeof(PackedBinaryReader<TReader>).MakeByRefType(), typeof(PackedBinarySerializationContext)]
                );
                
                var il = callCtor.GetILGenerator();

                Dictionary<ParameterInfo, int> localIndex = new Dictionary<ParameterInfo, int>();

                foreach ((_, Type type, ParameterInfo parameter, _) in serializedOrder)
                {
                    LocalBuilder declareLocal = il.DeclareLocal(type);
                    localIndex.Add(parameter, declareLocal.LocalIndex);                    
                }
                
                foreach ((_, Type type, ParameterInfo parameter, _) in serializedOrder)
                {
                    il.Emit(OpCodes.Ldarg_0);
                    il.Emit(OpCodes.Ldarg_1);
                    il.Emit(OpCodes.Call, typeof(PackedBinaryReader<TReader>).GetMethod(nameof(ReflectedRead), BindingFlags.NonPublic | BindingFlags.Instance)!.MakeGenericMethod([type]));
                    switch (localIndex[parameter])
                    {
                        case 0: il.Emit(OpCodes.Stloc_0); break;
                        case 1: il.Emit(OpCodes.Stloc_1); break;
                        case 2: il.Emit(OpCodes.Stloc_2); break;
                        case 3: il.Emit(OpCodes.Stloc_3); break;
                        case var i: il.Emit(OpCodes.Stloc_S, i); break;
                    }
                }

                foreach ((_, _, ParameterInfo parameter, _) in parameterOrder)
                {
                    switch (localIndex[parameter])
                    {
                        case 0: il.Emit(OpCodes.Ldloc_0); break;
                        case 1: il.Emit(OpCodes.Ldloc_1); break;
                        case 2: il.Emit(OpCodes.Ldloc_2); break;
                        case 3: il.Emit(OpCodes.Ldloc_3); break;
                        case var i: il.Emit(OpCodes.Ldloc_S, i); break;
                    }
                }
                
                il.Emit(OpCodes.Newobj, constructorInfo);
                il.Emit(OpCodes.Ret);
                
                inCtor = ctorMembers.Select(m => m.member).ToList();
                return callCtor.CreateDelegate<RefInFunc<PackedBinaryReader<TReader>, PackedBinarySerializationContext, T>>();
            }
        }
    }

    private partial class MemberNameComparer : IEqualityComparer<string>
    {
        public static MemberNameComparer Default = new();

        [GeneratedRegex("[^a-zA-Z0-9]")]
        public partial Regex NonAlphaNum { get; }

        public bool Equals(string? x, string? y)
        {
            if (x is null) return y is null;
            if (y is null) return false;
            
            x = NonAlphaNum.Replace(x, "");
            y = NonAlphaNum.Replace(y, "");
            return StringComparer.OrdinalIgnoreCase.Equals(x, y);
        }

        public int GetHashCode(string obj)
        {
            obj = NonAlphaNum.Replace(obj, "");
            return StringComparer.OrdinalIgnoreCase.GetHashCode(obj);
        }
    }

    private PackedBinarySerializableAttribute GetEffectiveTypeAttribute(Type targetType)
    {
        PackedBinarySerializableAttribute? attr = targetType.GetCustomAttribute<PackedBinarySerializableAttribute>() ??
            _serializer.GetEffectiveSerializableAttribute(targetType);
        return attr ?? throw new ArgumentException($"Type {targetType.Name} is not serializable", nameof(targetType));
    }

    private static readonly DelegateCache<PackedBinaryReader<TReader>, (Type returnType, Type targetType, Type instanceType), Delegate>
        s_writeMembersCache = new();

    private void PopulateMembers<T>(Type targetType, T instance, IReadOnlyList<MemberInfo> inCtor, PackedBinarySerializationContext ctx)
        where T : notnull
    {
        if (!targetType.IsAssignableTo(typeof(T)))
            throw new ArgumentException($"Type {targetType.Name} is not assignable to {typeof(T).Name}", nameof(targetType));

        var combinedSetters = (RefInAction<PackedBinaryReader<TReader>, T, PackedBinarySerializationContext>)s_writeMembersCache.GetOrCreate(
            ref this,
            (typeof(T), targetType, instance.GetType()),
            BuildWriterDelegate
        );
        combinedSetters(ref this, instance, ctx);

        return;

        Delegate BuildWriterDelegate((Type returnType, Type targetType, Type instanceType) key, ref PackedBinaryReader<TReader> reader)
        {
            PackedBinarySerializableAttribute attr = reader.GetEffectiveTypeAttribute(key.targetType);

            IEnumerable<MemberInfo> targetMembers = key.targetType.GetMembers(
                    BindingFlags.Instance | BindingFlags.Public | (attr.IncludeNonPublic ? BindingFlags.NonPublic : 0)
                )
                .Where(a => a.GetCustomAttribute<PackedBinaryMemberIgnoreAttribute>() is null)
                .Where(m => !inCtor.Contains(m));
            if (!attr.SequentialMembers)
                targetMembers = targetMembers
                    .Select(member => (member, attr: member.GetCustomAttribute<PackedBinaryMemberAttribute>()))
                    .Where(x => x.attr is not null)
                    .OrderBy(x => x.attr!.Order)
                    .Select(x => x.member);

            RefInAction<PackedBinaryReader<TReader>, T, PackedBinarySerializationContext>? writeAllMembersDelegate = null;
            foreach (MemberInfo member in targetMembers)
            {
                Type? memberType = ReflectionHelpers.GetMemberType(member);
                if (memberType != null)
                {
                    var setter = GetMember<RefInAction<PackedBinaryReader<TReader>, T, MemberInfo, PackedBinarySerializationContext>>(
                        nameof(WriteMemberTypeCast),
                        key.instanceType,
                        key.returnType,
                        memberType
                    );
                    writeAllMembersDelegate += (scoped ref PackedBinaryReader<TReader> r, T i, PackedBinarySerializationContext c) =>
                    {
                        setter(ref r, i, member, c);
                    };
                }
            }

            return writeAllMembersDelegate ?? delegate(scoped ref PackedBinaryReader<TReader> arg, T arg2, PackedBinarySerializationContext arg3) {  };
        }
    }

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
        Func<MemberInfo, Action<TIn, TMember>> getSetter = GetMember<Func<MemberInfo, Action<TIn, TMember>>>(
            nameof(GetMemberAccess),
            typeof(TIn),
            typeof(TMember)
        );
        Action<TIn, TMember> setter = getSetter(member);
        setter(instance, reader.Read<TMember>(ctx));
    }

    private static TDelegate GetMember<TDelegate>(string name, params Type[] gtas)
        where TDelegate : Delegate
    {
        MethodInfo methodInfo = typeof(PackedBinaryReader<TReader>).GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic)!;
        MethodInfo genericInstance = methodInfo.MakeGenericMethod(gtas);
        return genericInstance.CreateDelegate<TDelegate>();
    }
}