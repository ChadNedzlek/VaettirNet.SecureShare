using System;
using System.IO;

namespace VaettirNet.PackedBinarySerialization.Buffers;

public class StreamBufferReader : IBufferReader<byte>
{
    private Stream _stream;
    private byte[] _buffer;
    private int _index;
    private int _filled;

    public StreamBufferReader(Stream stream, int bufferSize = 0)
    {
        _stream = stream;
        _buffer = new byte[bufferSize == 0 ? 4000 : bufferSize];
    }

    public ReadOnlySpan<byte> GetSpan(int sizeHint)
    {
        if (sizeHint > _filled - _index)
        {
            return _buffer[_index.._filled];
        }

        FillBuffer(sizeHint);
        return _buffer[_index.._filled];
    }

    public ReadOnlyMemory<byte> GetMemory(int sizeHint)
    {
        if (sizeHint > _filled - _index)
        {
            return _buffer[_index.._filled];
        }

        FillBuffer(sizeHint);
        return _buffer[_index.._filled];
    }

    private void FillBuffer(int sizeHint)
    {
        var newBuffer = new byte[int.Max(_buffer.Length, sizeHint)];
        _buffer.AsSpan(_index).CopyTo(newBuffer);
        _filled -= _index;
        _index = 0;
        sizeHint -= _filled;
        var unwrittenSpan = newBuffer.AsSpan(_filled);
        var read = _stream.ReadAtLeast(unwrittenSpan, sizeHint, throwOnEndOfStream: false);
        _filled = _index + read;
    }

    public void Advance(int count)
    {
        if (count <= 0 || count >= (_filled - _index))
            throw new ArgumentOutOfRangeException();
        
        _index += count;
    }
}