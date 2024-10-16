using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using VaettirNet.CodeGeneration.DelegateImplementation;

namespace VaettirNet.SecureShare.Serialization;

internal partial class FixedSizeUnmanagedMemoryStream : Stream
{
    [DelegateImplementation(IncludeVirtual = true)]
    private readonly UnmanagedMemoryStream _baseStream;
    
    public bool IsExhausted { get; private set; }

    public FixedSizeUnmanagedMemoryStream(UnmanagedMemoryStream baseStream)
    {
        _baseStream = baseStream;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (count + Length > _baseStream.Capacity)
        {
            IsExhausted = true;
            return;
        }
        
        _baseStream.Write(buffer, offset, count);
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length + Length > _baseStream.Capacity)
        {
            IsExhausted = true;
            return;
        }
        _baseStream.Write(buffer);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        if (count + Length > _baseStream.Capacity)
        {
            IsExhausted = true;
            return Task.CompletedTask;
        }
        
        return _baseStream.WriteAsync(buffer, offset, count, cancellationToken);
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.Length + Length > _baseStream.Capacity)
        {
            IsExhausted = true;
            return ValueTask.CompletedTask;
        }
        return _baseStream.WriteAsync(buffer, cancellationToken);
    }

    public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback? callback, object? state)
    {
        if (count + Length > _baseStream.Capacity)
        {
            IsExhausted = true;
            return _baseStream.BeginWrite(buffer, offset, 0, callback, state);
        }
        return _baseStream.BeginWrite(buffer, offset, count, callback, state);
    }

    public override void WriteByte(byte value)
    {
        if (1 + Length > _baseStream.Capacity)
        {
            IsExhausted = true;
            return;
        }
        _baseStream.WriteByte(value);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _baseStream.Dispose();
        }
        base.Dispose(disposing);
    }
}