using System;
using System.Buffers;
using System.IO;
using ProtoBuf.Meta;

namespace VaettirNet.SecureShare.Serialization;

public class ProtobufObjectSerializer<T> : IBinarySerializer<T>
{
    private readonly RuntimeTypeModel _typeModel;

    private ProtobufObjectSerializer(params ReadOnlySpan<Type> additionalTypes)
    {
        _typeModel = RuntimeTypeModel.Create();
        _typeModel.Add<T>();
        _typeModel.SetSurrogate<DateTimeOffset, long>(DateTimeOffsetToTicksUtc, TicksToDateTimeOffsetUtc);
        foreach (Type? type in additionalTypes) _typeModel.Add(type);
    }

    private ProtobufObjectSerializer(Action<RuntimeTypeModel> customize)
    {
        _typeModel = RuntimeTypeModel.Create();
        _typeModel.Add<T>();
        _typeModel.SetSurrogate<DateTimeOffset, long>(DateTimeOffsetToTicksUtc, TicksToDateTimeOffsetUtc);
        customize(_typeModel);
    }

    private static ProtobufObjectSerializer<T> Instance { get; } = new();

    public bool TrySerialize(T value, Span<byte> destination, out int bytesWritten)
    {
        unsafe
        {
            fixed (byte* buffer = &destination.GetPinnableReference())
            {
                FixedSizeUnmanagedMemoryStream s = new(new UnmanagedMemoryStream(buffer, 0, destination.Length, FileAccess.Write));
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
                using PointerMemoryManager mm = new(buffer, source.Length);
                return (T)_typeModel.Deserialize(mm.Memory, type: typeof(T));
            }
        }
    }

    private static DateTimeOffset TicksToDateTimeOffsetUtc(long t)
    {
        return new DateTimeOffset(t, TimeSpan.Zero);
    }

    private static long DateTimeOffsetToTicksUtc(DateTimeOffset d)
    {
        return d.UtcTicks;
    }

    public static ProtobufObjectSerializer<T> Create(params ReadOnlySpan<Type> additionalTypes)
    {
        if (additionalTypes.IsEmpty)
            return Instance;

        foreach (Type? type in additionalTypes)
        {
        }

        return new ProtobufObjectSerializer<T>(additionalTypes);
    }

    public static ProtobufObjectSerializer<T> Create(Action<RuntimeTypeModel> customize)
    {
        return new ProtobufObjectSerializer<T>(customize);
    }

    public void Serialize(Stream stream, T value)
    {
        _typeModel.Serialize(stream, value);
    }

    public T Deserialize(Stream source)
    {
        return (T)_typeModel.Deserialize(source, null, typeof(T));
    }

    private sealed unsafe class PointerMemoryManager : MemoryManager<byte>
    {
        private readonly int _length;
        private readonly void* _pointer;

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