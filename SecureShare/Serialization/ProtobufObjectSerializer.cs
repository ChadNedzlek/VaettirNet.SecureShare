using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using ProtoBuf;
using ProtoBuf.Meta;

namespace VaettirNet.SecureShare.Serialization;

public class ProtobufObjectSerializer 
{
    private static ProtobufObjectSerializer Instance { get; } = new ();

    public static ProtobufObjectSerializer Create(Type type)
    {
        ValidateType(type);
        return Instance;
    }
    
    public static IBinarySerializer<T> Create<T>() where T : IBinarySerializable<T>
    {
        ValidateType(typeof(T));
        return GetTypedWrapper<T>();
    }

    private static TypedWrapper<T> GetTypedWrapper<T>() where T : IBinarySerializable<T>
    {
        return TypedWrapper<T>.TypedInstance;
    }

    private class TypedWrapper<T> : IBinarySerializer<T> where T : IBinarySerializable<T>
    {
        public static TypedWrapper<T> TypedInstance { get; } = new();

        public bool TrySerialize(T value, Span<byte> destination, out int bytesWritten)
            => Instance.TrySerialize(value, typeof(T), destination, out bytesWritten);

        public T Deserialize(ReadOnlySpan<byte> source)
            => (T)Instance.Deserialize(source, typeof(T));
    }

    protected static void ValidateType(Type type)
    {
        IList<CustomAttributeData> attrData = type.GetCustomAttributesData();
        if (attrData.All(a => a.AttributeType != typeof(ProtoContractAttribute)))
        {
            throw new ArgumentException($"Type {type.Name} must have [ProtoContract]");
        }

        if (type.GetConstructor([]) == null)
        {
            throw new ArgumentException($"Type {type.Name} must have parameterless constructor");
        }
    }

    private bool TrySerialize(object value, Type type, Span<byte> destination, out int bytesWritten)
    {
        unsafe
        {
            fixed (byte* buffer = &destination.GetPinnableReference())
            {
                UnmanagedMemoryStream s = new(buffer, 0, destination.Length, FileAccess.Write);
                TypeModel typeModel = RuntimeTypeModel.CreateForAssembly(type);
                try
                {
                    typeModel.Serialize(s, value);
                }
                catch (NotSupportedException)
                {
                    // UnmanagedMemoryStream, annoyingly, throws a NotSupportedException if 
                    // too much is written, with no real useful information,
                    // so we need to catch that and be sad
                    bytesWritten = 0;
                    return false;
                }

                s.Flush();
                bytesWritten = (int)s.Length;
                return true;
            }
        }
    }

    private object Deserialize(ReadOnlySpan<byte> source, Type type)
    {
        unsafe
        {
            fixed (byte* buffer = &source.GetPinnableReference())
            {
                using PointerMemoryManager<byte> mm = new(buffer, source.Length);
                return RuntimeTypeModel.CreateForAssembly(type).Deserialize(mm.Memory, type:type);
            }
        }
    }

    private sealed unsafe class PointerMemoryManager<T> : MemoryManager<T> where T : struct
    {
        private readonly void* _pointer;
        private readonly int _length;

        internal PointerMemoryManager(void* pointer, int length)
        {
            _pointer = pointer;
            _length = length;
        }

        protected override void Dispose(bool disposing)
        {
        }

        public override Span<T> GetSpan()
        {
            return new Span<T>(_pointer, _length);
        }

        public override MemoryHandle Pin(int elementIndex = 0)
        {
            throw new NotSupportedException();
        }

        public override void Unpin()
        {
        }
    }
}