using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using ProtoBuf;
using ProtoBuf.Meta;

namespace VaettirNet.SecureShare.Serialization;

public class ProtobufObjectSerializer<T> : IBinarySerializer<T>
    where T : IBinarySerializable<T>
{
    private readonly TypeModel _typeModel;
    private static ProtobufObjectSerializer<T> Instance { get; } = new ();

    private ProtobufObjectSerializer()
    {
        var model = RuntimeTypeModel.Create();
        model.Add<T>();
        _typeModel = model.Compile();
    }

    public static IBinarySerializer<T> Create()
    {
        ValidateType(typeof(T));
        return Instance;
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

    public bool TrySerialize(T value, Span<byte> destination, out int bytesWritten)
    {
        unsafe
        {
            fixed (byte* buffer = &destination.GetPinnableReference())
            {
                FixedSizeUnmanagedMemoryStream s = new(new(buffer, 0, destination.Length, FileAccess.Write));
                _typeModel.Serialize(s, value);
                if (s.IsExhausted)
                {
                    bytesWritten = 0;
                    return false;
                }

                s.Flush();
                bytesWritten = (int)s.Length;
                return true;
            }
        }
    }

    public T Deserialize(ReadOnlySpan<byte> source)
    {
        unsafe
        {
            fixed (byte* buffer = &source.GetPinnableReference())
            {
                using PointerMemoryManager<byte> mm = new(buffer, source.Length);
                return (T)_typeModel.Deserialize(mm.Memory, type:typeof(T));
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