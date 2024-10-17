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

    private ProtobufObjectSerializer(params ReadOnlySpan<Type> additionalTypes)
    {
        var model = RuntimeTypeModel.Create();
        model.Add<T>();
        foreach (var type in additionalTypes)
        {
            model.Add(type);
        }
        _typeModel = model.Compile();
    }
    
    private ProtobufObjectSerializer(Action<RuntimeTypeModel> customize)
    {
        var model = RuntimeTypeModel.Create();
        model.Add<T>();
        customize(model);
        _typeModel = model;
    }

    public static IBinarySerializer<T> Create(params ReadOnlySpan<Type> additionalTypes)
    {
        ValidateType(typeof(T));
        if (additionalTypes.IsEmpty)
            return Instance;

        foreach (var type in additionalTypes)
        {
            ValidateType(type);
        }

        return new ProtobufObjectSerializer<T>(additionalTypes);
    }

    public static ProtobufObjectSerializer<T> Create(Action<RuntimeTypeModel> customize)
    {
        ValidateType(typeof(T));
        return new ProtobufObjectSerializer<T>(customize);
    }

    private static void ValidateType(Type type)
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

    public void Serialize(Stream stream, T value)
    {
        _typeModel.Serialize(stream, value);
    }

    public T Deserialize(ReadOnlySpan<byte> source)
    {
        unsafe
        {
            fixed (byte* buffer = &source.GetPinnableReference())
            {
                using PointerMemoryManager mm = new(buffer, source.Length);
                return (T)_typeModel.Deserialize(mm.Memory, type:typeof(T));
            }
        }
    }

    public T Deserialize(Stream source)
    {
        return (T)_typeModel.Deserialize(source, null, typeof(T));
    }

    private sealed unsafe class PointerMemoryManager : MemoryManager<byte>
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

        public override Span<byte> GetSpan()
        {
            return new Span<byte>(_pointer, _length);
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