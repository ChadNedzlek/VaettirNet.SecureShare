using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Threading;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryReader<TReader>
{
    public sbyte ReadSByte(PackedBinarySerializationContext ctx)
    {
        sbyte ret = (sbyte)_reader.GetSpan(1)[0];
        _reader.Advance(1);
        return ret;
    }

    public short ReadInt16(PackedBinarySerializationContext ctx)
    {
        if (ctx.UsePackedIntegers)
            return (short)ReadInt64(ctx);

        return ReadCore(ref _reader);

        static short ReadCore(ref TReader reader)
        {
            var span = reader.GetSpan(2);
            var ret = BinaryPrimitives.ReadInt16BigEndian(span);
            reader.Advance(2);
            return ret;
        }
    }

    public int ReadInt32(PackedBinarySerializationContext ctx)
    {
        if (ctx.UsePackedIntegers)
            return (int)ReadInt64(ctx);

        return ReadCore(ref _reader);

        static int ReadCore(ref TReader reader)
        {
            var span = reader.GetSpan(4);
            var ret = BinaryPrimitives.ReadInt32BigEndian(span);
            reader.Advance(4);
            return ret;
        }
    }

    public long ReadInt64(PackedBinarySerializationContext ctx)
    {
        if (!ctx.UsePackedIntegers)
            return ReadCore(ref _reader);

        return ReadPacked(ref _reader);

        static long ReadCore(ref TReader reader)
        {
            var span = reader.GetSpan(8);
            var ret = BinaryPrimitives.ReadInt64BigEndian(span);
            reader.Advance(8);
            return ret;
        }

        static long ReadPacked(ref TReader reader)
        {
            var span = reader.GetSpan(10);
            byte b = span[0];
            bool move = (b & 0x80) != 0;
            if (!move)
            {
                reader.Advance(1);
                return (sbyte)(b << 1) >> 1;
            }

            long value = (sbyte)((sbyte)b << 1 & 0xFF) >> 1;
            int i = 0;
            while (move)
            {
                i++;
                b = span[i];
                move = (b & 0x80) != 0;
                value = (value << 7) | (byte)(b & 0x7F);
            }

            reader.Advance(i + 1);
            return value;
        }
    }

    public byte ReadByte(PackedBinarySerializationContext ctx)
    {
        var span = _reader.GetSpan(1);
        var ret = span[0];
        _reader.Advance(1);
        return ret;
    }

    public ushort ReadUInt16(PackedBinarySerializationContext ctx)
    {
        if (ctx.UsePackedIntegers)
            return (ushort)ReadInt64(ctx);

        return ReadCore(ref _reader);

        static ushort ReadCore(ref TReader reader)
        {
            var span = reader.GetSpan(2);
            var ret = BinaryPrimitives.ReadUInt16BigEndian(span);
            reader.Advance(2);
            return ret;
        }
    }

    public uint ReadUInt32(PackedBinarySerializationContext ctx)
    {
        if (ctx.UsePackedIntegers)
            return (uint)ReadInt64(ctx);

        return ReadCore(ref _reader);

        static uint ReadCore(ref TReader reader)
        {
            var span = reader.GetSpan(4);
            var ret = BinaryPrimitives.ReadUInt32BigEndian(span);
            reader.Advance(4);
            return ret;
        }
    }

    public ulong ReadUInt64(PackedBinarySerializationContext ctx)
    {
        if (ctx.UsePackedIntegers)
            return (ulong)ReadInt64(ctx);

        return ReadCore(ref _reader);

        static ulong ReadCore(ref TReader reader)
        {
            var span = reader.GetSpan(8);
            var ret = BinaryPrimitives.ReadUInt64BigEndian(span);
            reader.Advance(8);
            return ret;
        }
    }

    public float ReadSingle(PackedBinarySerializationContext ctx)
    {
        var span = _reader.GetSpan(sizeof(float));
        var ret = BinaryPrimitives.ReadSingleBigEndian(span);
        _reader.Advance(sizeof(float));
        return ret;
    }

    public double ReadDouble(PackedBinarySerializationContext ctx)
    {
        var span = _reader.GetSpan(sizeof(double));
        var ret = BinaryPrimitives.ReadDoubleBigEndian(span);
        _reader.Advance(sizeof(double));
        return ret;
    }

    public string? ReadString(PackedBinarySerializationContext ctx)
    {
        Encoding e = ctx.Encoding ?? Encoding.UTF8;
        int len = ReadInt32(ctx with { UsePackedIntegers = true });
        if (len == 0)
            return null;

        ReadOnlySpan<byte> span = _reader.GetSpan(len);
        string str = e.GetString(span[..len]);
        _reader.Advance(len);
        return str;
    }

    public bool ReadBool(PackedBinarySerializationContext ctx)
    {
        bool value = _reader.GetSpan(1)[0] != 0;
        _reader.Advance(1);
        return value;
    }

    public char ReadChar(PackedBinarySerializationContext ctx)
    {
        return (char)ReadUInt16(ctx);
    }
    private partial class ReflectionDelegate
    {
        private readonly string _name;
        private readonly ReaderWriterLockSlim _lock = new();
        private readonly Dictionary<Type, Delegate> _serializers = [];
        private readonly Func<Type, Type[]> _methodArgs;

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