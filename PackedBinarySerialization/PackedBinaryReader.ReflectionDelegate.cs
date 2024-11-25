using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryReader<TReader>
{
    private class ReflectionDelegate
    {
        public delegate TOutput ReadDelegate<out TOutput>(scoped ref PackedBinaryReader<TReader> reader, PackedBinarySerializationContext ctx)
            where TOutput : allows ref struct;
        
        private readonly string _name;
        private readonly ReaderWriterLockSlim _lock = new();
        private readonly Dictionary<Type, Delegate> _serializers = [];
        private readonly Func<Type, Type[]> _methodArgs;

        public ReflectionDelegate(string name, Func<Type, Type[]>? getTypes = null)
        {
            _methodArgs = getTypes ?? (t => t.GetGenericArguments());
            _name = name;
        }

        public ReadDelegate<TOutput> GetSerializer<TOutput>(Type type)
            where TOutput : allows ref struct
        {
            _lock.EnterReadLock();
            try
            {
                if (_serializers.TryGetValue(type, out var func))
                {
                    return (ReadDelegate<TOutput>)func;
                }
            }
            finally
            {
                _lock.ExitReadLock();
            }

            _lock.EnterWriteLock();
            try
            {
                if (_serializers.TryGetValue(type, out var func))
                {
                    return (ReadDelegate<TOutput>)func;
                }
            
                var callback = typeof(PackedBinaryReader<TReader>)
                    .GetMethod(_name, BindingFlags.Static | BindingFlags.NonPublic)!
                    .MakeGenericMethod(_methodArgs(type))
                    .CreateDelegate<ReadDelegate<TOutput>>();
            
                _serializers.Add(type, callback);
                return callback;
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }
    }
}