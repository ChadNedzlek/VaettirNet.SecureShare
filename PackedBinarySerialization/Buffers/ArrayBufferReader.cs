using System;

namespace VaettirNet.PackedBinarySerialization.Buffers;

public class ArrayBufferReader<T> : IBufferReader<T>
{
    private readonly T[] _buffer;
    private int _index;

    public ArrayBufferReader(T[] buffer)
    {
        _buffer = buffer;
    }

    public ReadOnlySpan<T> GetSpan(int sizeHint)
    {
        if (sizeHint > _buffer.Length - _index)
            return _buffer.AsSpan(_index);

        return _buffer.AsSpan(_index, sizeHint);
    }

    public ReadOnlyMemory<T> GetMemory(int sizeHint)
    {
        if (sizeHint > _buffer.Length - _index)
            return _buffer.AsMemory(_index);

        return _buffer.AsMemory(_index, sizeHint);
    }

    public void Advance(int count)
    {
        if (count > _buffer.Length - _index)
            throw new ArgumentOutOfRangeException();

        _index += count;
    }
}