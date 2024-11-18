using System;

namespace VaettirNet.PackedBinarySerialization.Buffers;

public ref struct SpanBufferReader<T> : IBufferReader<T>
{
    private ReadOnlySpan<T> _span;

    public SpanBufferReader(ReadOnlySpan<T> span)
    {
        _span = span;
    }

    public ReadOnlySpan<T> GetSpan(int sizeHint)
    {
        return _span;
    }

    public ReadOnlyMemory<T> GetMemory(int sizeHint)
    {
        throw new NotSupportedException();
    }

    public void Advance(int count)
    {
        _span = _span[count..];
    }
}