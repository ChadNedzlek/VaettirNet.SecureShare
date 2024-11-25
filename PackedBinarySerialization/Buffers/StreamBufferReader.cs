using System;
using System.IO;

namespace VaettirNet.PackedBinarySerialization.Buffers;

public class StreamBufferReader : IBufferReader<byte>
{
    private byte[] _buffer;
    private int _filled;
    private int _index;
    private readonly Stream _stream;

    public StreamBufferReader(Stream stream, int bufferSize = 0)
    {
        _stream = stream;
        _buffer = new byte[bufferSize == 0 ? 4000 : bufferSize];
    }

    public ReadOnlySpan<byte> GetSpan(int sizeHint)
    {
        if (sizeHint <= _filled - _index) return _buffer.AsSpan()[_index.._filled];

        FillBuffer(sizeHint);
        return _buffer.AsSpan()[_index.._filled];
    }

    public ReadOnlyMemory<byte> GetMemory(int sizeHint)
    {
        if (sizeHint <= _filled - _index) return _buffer.AsMemory()[_index.._filled];

        FillBuffer(sizeHint);
        return _buffer.AsMemory()[_index.._filled];
    }

    public void Advance(int count)
    {
        if (count <= 0 || count > _filled - _index)
            throw new ArgumentOutOfRangeException();

        _index += count;
    }

    private void FillBuffer(int sizeHint)
    {
        if (_filled == _index)
        {
            Array.Resize(ref _buffer, int.Max(_buffer.Length, sizeHint));
            _index = 0;
            int read = _stream.ReadAtLeast(_buffer, sizeHint, false);
            _filled = _index + read;
            return;
        }

        {
            byte[] newBuffer = new byte[int.Max(_buffer.Length, sizeHint)];
            _buffer.AsSpan(_index).CopyTo(newBuffer);
            _filled -= _index;
            _index = 0;
            sizeHint -= _filled;
            Span<byte> unwrittenSpan = newBuffer.AsSpan(_filled);
            int read = _stream.ReadAtLeast(unwrittenSpan, sizeHint, false);
            _filled += read;
            _buffer = newBuffer;
        }
    }
}