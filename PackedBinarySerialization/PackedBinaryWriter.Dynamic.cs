using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Threading;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryWriter<TWriter>
{
    public bool TryWriteWithMetadata<T>(object? value, PackedBinarySerializationContext ctx, out int written)
    {
        if (typeof(T).GetCustomAttribute<PackedBinarySerializableAttribute>() is { } attr)
        {
            if (value is null)
            {
                written = WriteBool(false, ctx);
                return true;
            }
            
            written = WriteBool(true, ctx);
            written += WriteWithMetadataCore<T>((T)value, ctx, attr);
            return true;
        }

        written = 0;
        return false;
    }

    public int WriteWithMetadata<T>(T value, PackedBinarySerializationContext ctx) =>
        WriteWithMetadataCore(value, ctx, typeof(T).GetCustomAttribute<PackedBinarySerializableAttribute>()!);

    private static readonly Dictionary<(Type serializer, Type valueType), (int revision, Delegate factory)> s_reflectionCache = [];
    private readonly ReaderWriterLockSlim s_reflectionLock = new();

    private delegate int WriteMetadataDelegate<T>(ref PackedBinaryWriter<TWriter> writer, T value, PackedBinarySerializationContext ctx);
    
    private int WriteWithMetadataCore<T>(T value, PackedBinarySerializationContext ctx, PackedBinarySerializableAttribute attr)
    {
        return GetMetadataWriteDelegate<T>(attr).Invoke(ref this, value, ctx);
    }

    private void WriteValue<T>(ref PackedBinaryWriter<TWriter> writer, T value, ref int written, PackedBinarySerializationContext ctx)
    {
        written += writer.Write(value, ctx);
    }

    private static Type? GetMemberType(MemberInfo member) => member switch {
        FieldInfo fieldInfo => fieldInfo.FieldType,
        PropertyInfo propertyInfo => propertyInfo.PropertyType,
        _ => null,
    };

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
            DynamicMethod getter = new DynamicMethod($"{typeof(TObj).Name}_Get_{fieldInfo.Name}", typeof(TMember), [typeof(TObj)]);
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
    
    private static WriteMemberStaticDelegate<TObj>? BuildWriteMember<TObj>(MemberInfo member)
    {
        if (GetMemberType(member) is not { } memberType)
        {
            return null;
        }

        var method = typeof(PackedBinaryWriter<TWriter>).GetMethod(nameof(BuildWriteMemberTyped), BindingFlags.Static | BindingFlags.NonPublic);
        return method.MakeGenericMethod(typeof(TObj), memberType)
            .CreateDelegate<Func<MemberInfo, WriteMemberStaticDelegate<TObj>>>()
            .Invoke(member);
    }

    private static WriteMemberStaticDelegate<TObj>? BuildWriteMemberTyped<TObj, TMember>(MemberInfo member)
    {
        Func<TObj, TMember>? access = GetMemberAccess<TObj, TMember>(member);
        if (access == null)
            return null;
        var method = typeof(PackedBinaryWriter<TWriter>).GetMethod(nameof(WriteMemberStatic), BindingFlags.Static | BindingFlags.NonPublic);
        var makeIt = method!.MakeGenericMethod(typeof(TObj), typeof(TMember)).CreateDelegate<WriteMemberStaticCallbackDelegate<TObj>>();
        return WriteMember;

        void WriteMember(ref PackedBinaryWriter<TWriter> writer, TObj value, PackedBinarySerializationContext ctx, ref int written)
        {
            makeIt(ref writer, value, access, ctx, ref written);
        }
    }

    private WriteMetadataDelegate<T> GetMetadataWriteDelegate<T>(PackedBinarySerializableAttribute attr)
    {
        WriteMemberStaticDelegate<T> build = null;
        var targetMembers = typeof(T).GetMembers(
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

        foreach (MemberInfo member in targetMembers)
        {
            if (BuildWriteMember<T>(member) is { } callback)
            {
                build += callback;
            }
        }
        
        return delegate(ref PackedBinaryWriter<TWriter> writer, T value, PackedBinarySerializationContext ctx)
        {
            int written = 0;
            build?.Invoke(ref writer, value, ctx, ref written);
            return written;
        };
    }

    private WriteMetadataDelegate<T> BuildMetadataWriteDelegate<T>(PackedBinarySerializableAttribute attr)
    {
        throw new NotImplementedException();
    }
}