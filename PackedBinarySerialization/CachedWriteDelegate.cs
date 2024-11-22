namespace VaettirNet.PackedBinarySerialization;

internal class CachedSerializerDelegate<TRef, TKey, TValue>
    where TRef : allows ref struct
    where TKey : notnull
{
    public CachedSerializerDelegate(int serializerRevision)
    {
        SerializerRevision = serializerRevision;
    }

    public int SerializerRevision { get; }
    public DelegateCache<TRef, TKey, TValue> Delegates { get; } = new();
}