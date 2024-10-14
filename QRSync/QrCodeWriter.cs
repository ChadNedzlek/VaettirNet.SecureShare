using System;
using System.Collections;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Net.Codecrete.QrCodeGenerator;
using ZXing.QrCode;

namespace QrSync;

public static class QrCodeWriter
{
    public static bool TryWritePng(ReadOnlySpan<byte> data, Span<byte> output, out int cb)
    {
        var ret = GetPngData(data);
        cb = ret.Length;
        if (output.Length < ret.Length)
        {
            return false;
        }
        ret.CopyTo(output);
        return true;
    }
    
    public static void WritePng(ReadOnlySpan<byte> data, Stream stream)
    {
        byte[] ret = GetPngData(data);
        stream.Write(ret);
    }
    
    public static ReadOnlyMemory<byte> WritePng(ReadOnlySpan<byte> data) => GetPngData(data);

    public static ValueTask WritePngAsync(ReadOnlySpan<byte> data, Stream stream, CancellationToken cancellationToken = default)
    {
        var ret = GetPngData(data);
        return stream.WriteAsync(ret, cancellationToken);
    }
    
    public static void WritePng(ReadOnlySpan<byte> data, string file)
    {
        byte[] ret = GetPngData(data);
        File.WriteAllBytes(file, ret);
    }
    
    public static Task WritePngAsync(ReadOnlySpan<byte> data, string file, CancellationToken cancellationToken = default)
    {
        byte[] ret = GetPngData(data);
        return File.WriteAllBytesAsync(file, ret, cancellationToken);
    }

    private static byte[] GetPngData(ReadOnlySpan<byte> bytes)
    {
        byte[] arr = new byte[bytes.Length];
        bytes.CopyTo(arr);
        QrCode data = QrCode.EncodeBinary(arr, QrCode.Ecc.Low)!;
        return data.ToPng(4, 4);
    }
}