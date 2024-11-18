using System.Buffers.Binary;
using System.Text;

namespace VaettirNet.PackedBinarySerialization;

public ref partial struct PackedBinaryWriter<TWriter>
{
    public int WriteString(string? value, PackedBinarySerializationContext ctx)
    {
        if (value == null)
        {
            _writer.GetSpan(1)[0] = 0;
            _writer.Advance(1);
            return 1;
        }

        Encoding encoding = ctx.Encoding ?? Encoding.UTF8;
        int maxByteCount = encoding.GetMaxByteCount(value.Length);
        var sizeSize = GetNumberSize((ulong)maxByteCount);
        var span = _writer.GetSpan(sizeSize + maxByteCount);
        int read = encoding.GetBytes(value, span[sizeSize..]);
        WriteInt32(read, ctx with { MaxValue = maxByteCount, UsePackedIntegers = true});
        _writer.Advance(read);
        return sizeSize + read;
    }

    public int WriteByte(byte value, PackedBinarySerializationContext ctx)
    {
        _writer.GetSpan(1)[0] = value;
        _writer.Advance(1);
        return 1;
    }

    public int WriteSByte(sbyte value, PackedBinarySerializationContext ctx)
    {
        _writer.GetSpan(1)[0] = (byte)value;
        _writer.Advance(1);
        return 1;
    }

    public int WriteInt16(short value, PackedBinarySerializationContext ctx)
    {
        if (ctx.UsePackedIntegers)
        {
            return WriteInt64(value, ctx);
        }

        return WriteCore(ref _writer, value);

        int WriteCore(ref TWriter writer, short value)
        {
            const int size = sizeof(short);
            var span = writer.GetSpan(size);
            BinaryPrimitives.WriteInt16BigEndian(span, value);
            writer.Advance(size);
            return size;
        }
    }

    public int WriteUInt16(ushort value, PackedBinarySerializationContext ctx)
    {
        if (ctx.UsePackedIntegers)
        {
            return WriteInt64(value, ctx);
        }

        return WriteCore(ref _writer, value);

        int WriteCore(ref TWriter writer, ushort value)
        {
            const int size = sizeof(ushort);
            var span = writer.GetSpan(size);
            BinaryPrimitives.WriteUInt16BigEndian(span, value);
            writer.Advance(size);
            return size;
        }
    }

    public int WriteInt32(int value, PackedBinarySerializationContext ctx)
    {
        if (ctx.UsePackedIntegers)
        {
            return WriteInt64(value, ctx);
        }

        return WriteCore(ref _writer, value);

        int WriteCore(ref TWriter writer, int value)
        {
            const int size = sizeof(int);
            var span = writer.GetSpan(size);
            BinaryPrimitives.WriteInt32BigEndian(span, value);
            writer.Advance(size);
            return size;
        }
    }

    public int WriteUInt32(uint value, PackedBinarySerializationContext ctx)
    {
        if (ctx.UsePackedIntegers)
        {
            return WriteInt64(value, ctx);
        }

        return WriteCore(ref _writer, value);

        int WriteCore(ref TWriter writer, uint value)
        {
            const int size = sizeof(uint);
            var span = writer.GetSpan(size);
            BinaryPrimitives.WriteUInt32BigEndian(span, value);
            writer.Advance(size);
            return size;
        }
    }

    public int WriteInt64(long value, PackedBinarySerializationContext ctx)
    {
        if (!ctx.UsePackedIntegers)
        {
            return WriteCore(ref _writer, value);
        }

        return WritePacked(ref _writer, value, ctx.MaxValue);

        int WriteCore(ref TWriter writer, long value)
        {
            const int size = sizeof(long);
            var span = writer.GetSpan(size);
            BinaryPrimitives.WriteInt64BigEndian(span, value);
            writer.Advance(size);
            return size;
        }

        int WritePacked(ref TWriter writer, long value, long? maxValue)
        {
            long left = value;
            if (left == 0)
            {
                writer.GetSpan(1)[0] = 0;
                writer.Advance(1);
                return 1;
            }

            if (left == -1)
            {
                writer.GetSpan(1)[0] = 0x7F;
                writer.Advance(1);
                return 1;
            }

            var span = writer.GetSpan(9);
            int c = 0;
            long tracking = maxValue ?? left;
            while (tracking is not 0 and not -1)
            {
                c++;
                if (((ulong)tracking & 0xFFFF_FFFF_FFFF_FFC0) is 0x40 or 0xFFFF_FFFF_FFFF_FF80)
                {
                    c++;
                    break;
                }

                tracking >>= 7;
            }

            for (int i = 0; i < c; i++)
            {
                int shift = (c - i - 1) * 7;
                byte b = (byte)((byte)(left >> shift) & 0x7F);
                if (shift != 0)
                    b |= 0x80;
                span[i] = b;
            }

            writer.Advance(c);
            return c;
        }
    }

    public int WriteUInt64(ulong value, PackedBinarySerializationContext ctx)
    {
        if (ctx.UsePackedIntegers)
        {
            return WriteInt64((long)value, ctx);
        }

        return WriteCore(ref _writer, value);

        int WriteCore(ref TWriter writer, ulong value)
        {
            const int size = sizeof(ulong);
            var span = writer.GetSpan(size);
            BinaryPrimitives.WriteUInt64BigEndian(span, value);
            writer.Advance(size);
            return size;
        }
    }

    public int WriteSingle(float value, PackedBinarySerializationContext ctx)
    {
        const int size = sizeof(float);
        var span = _writer.GetSpan(size);
        BinaryPrimitives.WriteSingleBigEndian(span, value);
        _writer.Advance(size);
        return size;
    }

    public int WriteDouble(double value, PackedBinarySerializationContext ctx)
    {
        const int size = sizeof(double);
        var span = _writer.GetSpan(size);
        BinaryPrimitives.WriteDoubleBigEndian(span, value);
        _writer.Advance(size);
        return size;
    }

    public int WriteBool(bool value, PackedBinarySerializationContext ctx)
    {
        _writer.GetSpan(1)[0] = (byte)(value ? 1 : 0);
        _writer.Advance(1);
        return 1;
    }

    public int WriteChar(char value, PackedBinarySerializationContext ctx)
    {
        return WriteUInt16(value, ctx);
    }

    private int GetNumberSize(ulong value)
    {
        return value switch
        {
            < 1L << 7 * 1 => 1,
            < 1L << 7 * 2 => 2,
            < 1L << 7 * 3 => 3,
            < 1L << 7 * 4 => 4,
            < 1L << 7 * 5 => 5,
            < 1L << 7 * 6 => 6,
            < 1L << 7 * 7 => 7,
            < 1L << 7 * 8 => 8,
            < 1L << 7 * 8 + 6 => 9,
            _ => 10,
        };
    }
}