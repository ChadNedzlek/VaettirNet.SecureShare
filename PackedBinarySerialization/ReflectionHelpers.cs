using System;
using System.Reflection;

namespace VaettirNet.PackedBinarySerialization;

public static class ReflectionHelpers
{
    public static Type? GetMemberType(MemberInfo member) => member switch {
        FieldInfo fieldInfo => fieldInfo.FieldType,
        PropertyInfo propertyInfo => propertyInfo.PropertyType,
        _ => null,
    };
}