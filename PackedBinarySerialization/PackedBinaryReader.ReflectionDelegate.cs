using System;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryReader<TReader>
{
    private partial class ReflectionDelegate
    {
        public delegate TOutput ReadDelegate<out TOutput>(scoped ref PackedBinaryReader<TReader> writer, PackedBinarySerializationContext ctx)
            where TOutput : allows ref struct;

        public ReflectionDelegate(string name, Func<Type, Type[]>? getTypes = null)
        {
            _methodArgs = getTypes ?? (t => t.GetGenericArguments());
            _name = name;
        }
    }
}