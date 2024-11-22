using System.Collections.Generic;
using System.Threading;

namespace VaettirNet.PackedBinarySerialization;

internal class DelegateCache<TRef, TKey, TValue>
    where TRef : allows ref struct
    where TKey : notnull
{
    public delegate TValue CreateCallback(TKey key, scoped ref TRef refType);
        
    private readonly Dictionary<TKey, TValue> _cache = [];
    private readonly ReaderWriterLockSlim _lock = new();

    public TValue GetOrCreate(scoped ref TRef refType, TKey key, CreateCallback create)
    {
        _lock.EnterReadLock();
        try
        {
            if (_cache.TryGetValue(key, out var value))
            {
                return value;
            }
        }
        finally
        {
            _lock.ExitReadLock();
        }
            
        _lock.EnterWriteLock();
        try
        {
            if (_cache.TryGetValue(key, out var value))
            {
                return value;
            }

            _cache.Add(key, value = create(key, ref refType));
            return value;
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }
}