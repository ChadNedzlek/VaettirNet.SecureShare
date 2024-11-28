using System;
using System.Buffers;
using System.IO;
using VaettirNet.PackedBinarySerialization;

namespace VaettirNet.SecureShare.Serialization;

public class PackedBinaryObjectSerializer<T> : IBinarySerializer<T>
{
    private readonly PackedBinarySerializer _serializer;

    private PackedBinaryObjectSerializer(params ReadOnlySpan<Type> additionalTypes)
    {
        _serializer = new PackedBinarySerializer();
        _serializer.AddType<T>();
        _serializer.SetSurrogate<DateTimeOffset, long>(DateTimeOffsetToTicksUtc, TicksToDateTimeOffsetUtc);
        foreach (Type type in additionalTypes) _serializer.AddType(type);
    }

    private PackedBinaryObjectSerializer(Action<PackedBinarySerializer> customize)
    {
        _serializer = new PackedBinarySerializer();
        _serializer.AddType<T>();
        _serializer.SetSurrogate<DateTimeOffset, long>(DateTimeOffsetToTicksUtc, TicksToDateTimeOffsetUtc);
        customize(_serializer);
    }

    private static PackedBinaryObjectSerializer<T> Instance { get; } = new();

    public bool TrySerialize(T value, Span<byte> destination, out int bytesWritten)
    {
        unsafe
        {
            fixed (byte* buffer = &destination.GetPinnableReference())
            {
                FixedSizeUnmanagedMemoryStream s = new(new UnmanagedMemoryStream(buffer, 0, destination.Length, FileAccess.Write));
                _serializer.Serialize(s, value);
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
        return _serializer.Deserialize<T>(source);
    }

    private static DateTimeOffset TicksToDateTimeOffsetUtc(long t)
    {
        return new DateTimeOffset(t, TimeSpan.Zero);
    }

    private static long DateTimeOffsetToTicksUtc(DateTimeOffset d)
    {
        return d.UtcTicks;
    }

    public static PackedBinaryObjectSerializer<T> Create(params ReadOnlySpan<Type> additionalTypes)
    {
        if (additionalTypes.IsEmpty)
            return Instance;

        foreach (Type type in additionalTypes)
        {
        }

        return new PackedBinaryObjectSerializer<T>(additionalTypes);
    }

    public static PackedBinaryObjectSerializer<T> Create(Action<PackedBinarySerializer> customize)
    {
        return new PackedBinaryObjectSerializer<T>(customize);
    }

    public void Serialize(Stream stream, T value)
    {
        _serializer.Serialize(stream, value);
    }

    public T Deserialize(Stream source)
    {
        return _serializer.Deserialize<T>(source);
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