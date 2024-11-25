#nullable disable
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryWriter<TWriter>
{
    public delegate int WriteDelegate<in TInput>(scoped ref PackedBinaryWriter<TWriter> writer, TInput input, PackedBinarySerializationContext ctx);
    
    private class WriteReflectionDelegate
    {
        private readonly string _name;
        private readonly ReaderWriterLockSlim _lock = new();
        private readonly Dictionary<Type, Delegate> _serializers = [];
        private readonly Func<Type, Type[]> _methodArgs; 

        public WriteReflectionDelegate(string name, Func<Type, Type[]> getTypes = null)
        {
            _methodArgs = getTypes ?? (t => t.GetGenericArguments());
            _name = name;
        }

        public WriteDelegate<TInput> GetSerializer<TInput>(Type type)
        {
            _lock.EnterReadLock();
            try
            {
                if (_serializers.TryGetValue(type, out var func))
                {
                    return (WriteDelegate<TInput>)func;
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
                    return (WriteDelegate<TInput>)func;
                }

                MethodInfo methodInfo = typeof(PackedBinaryWriter<TWriter>)
                    .GetMethod(_name, BindingFlags.Static | BindingFlags.NonPublic)!;

                if (methodInfo.IsGenericMethod)
                {
                    methodInfo = methodInfo.MakeGenericMethod(_methodArgs(type));
                }

                var callback = methodInfo.CreateDelegate<WriteDelegate<TInput>>();
            
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