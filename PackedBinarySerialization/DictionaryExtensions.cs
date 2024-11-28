using System;
using System.Collections.Generic;

namespace VaettirNet.PackedBinarySerialization;

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