using System;

namespace VaettirNet.PackedBinarySerialization;

public interface IBufferReader<T>
{
    ReadOnlySpan<T> GetSpan(int sizeHint);
    ReadOnlyMemory<T> GetMemory(int sizeHint);
    void Advance(int count);
}