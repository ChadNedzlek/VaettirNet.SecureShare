using System;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace VaettirNet.PackedBinarySerialization;

public static class ReflectionHelpers
{
    public static Type? GetMemberType(MemberInfo member) => member switch {
        FieldInfo fieldInfo => fieldInfo.FieldType,
        PropertyInfo propertyInfo => propertyInfo.PropertyType,
        _ => null,
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static TOut As<TIn, TOut>(TIn value)
        where TOut : allows ref struct
    {
        ref TOut refVale = ref Unsafe.As<TIn, TOut>(ref value);
        return refVale;
    }
}