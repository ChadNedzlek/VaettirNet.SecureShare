using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SkiaSharp;
using ZXing;
using ZXing.Common;
using ZXing.Multi.QrCode;

namespace QRSync;

public class QrCodeReader
{
    [SupportedOSPlatform("windows")]
    public static IReadOnlyList<ReadOnlyMemory<byte>> GetCodesFromScreen()
    {
        Rectangle bounds = Interop.Monitors.GetVirtualScreenBounds();
        using Bitmap bitmap = new(bounds.Width, bounds.Height);
        using Graphics g = Graphics.FromImage(bitmap);
        g.CopyFromScreen(bounds.X, bounds.Y, 0, 0, bitmap.Size);

        return GetCodesFromBitmap(bitmap);
    }
    
    public static IReadOnlyList<ReadOnlyMemory<byte>> GetCodesFromImage(string filename)
    {
        using SKBitmap bitmap = SKBitmap.FromImage(SKImage.FromEncodedData(filename));
        return GetCodesFromBitmap(bitmap);
    }

    public static IReadOnlyList<ReadOnlyMemory<byte>> GetCodesFromImage(Stream stream)
    {
        using SKBitmap bitmap = SKBitmap.FromImage(SKImage.FromEncodedData(stream));
        return GetCodesFromBitmap(bitmap);
    }

    public static IReadOnlyList<ReadOnlyMemory<byte>> GetCodesFromImage(ReadOnlySpan<byte> bytes)
    {
        using SKBitmap bitmap = SKBitmap.FromImage(SKImage.FromEncodedData(bytes));
        return GetCodesFromBitmap(bitmap);
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<ReadOnlyMemory<byte>> GetCodesFromBitmap(Bitmap bitmap)
    {
        BitmapData data = bitmap.LockBits(new Rectangle(Point.Empty, bitmap.Size), ImageLockMode.ReadOnly, PixelFormat.Format16bppRgb565);
        byte[] rgbData;
        try
        {
            int cb = data.Stride * data.Height;
            rgbData = new byte[cb];
            Marshal.Copy(data.Scan0, rgbData, 0, cb);
        }
        finally
        {
            bitmap.UnlockBits(data);
        }

        Result[] results =
            new QRCodeMultiReader().decodeMultiple(
                new BinaryBitmap(new HybridBinarizer(new RGBLuminanceSource(rgbData,
                    bitmap.Width,
                    bitmap.Height,
                    RGBLuminanceSource.BitmapFormat.RGB565))),
                new Dictionary<DecodeHintType, object?> { { DecodeHintType.TRY_HARDER, null } });
        return results?.Select(r => (ReadOnlyMemory<byte>)r.RawBytes).ToList() ?? [];
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> GetCodesFromBitmap(SKBitmap bitmap)
    {
        RGBLuminanceSource.BitmapFormat bitmapFormat = GetBitmapType(bitmap.ColorType);

        IDisposable? dispose = null;
        byte[] rgbData;
        try
        {
            if (bitmapFormat == RGBLuminanceSource.BitmapFormat.Unknown)
            {
                SKBitmap original = bitmap;
                dispose = bitmap = new SKBitmap(original.Width, original.Height, SKColorType.Rgb565, SKAlphaType.Opaque);
                if (!original.CopyTo(bitmap, SKColorType.Rgb565))
                {
                    throw new ArgumentException("Could not copy image", nameof(bitmap));
                }
            }

            int cb = bitmap.RowBytes * bitmap.Height;
            rgbData = new byte[cb];
            Marshal.Copy(bitmap.GetPixels(), rgbData, 0, cb);
        }
        finally
        {
            dispose?.Dispose();
        }

        Result[] results =
            new QRCodeMultiReader().decodeMultiple(
                new BinaryBitmap(new HybridBinarizer(new RGBLuminanceSource(rgbData,
                    bitmap.Width,
                    bitmap.Height,
                    bitmapFormat))),
                new Dictionary<DecodeHintType, object?> { { DecodeHintType.TRY_HARDER, null } });

        RGBLuminanceSource.BitmapFormat GetBitmapType(SKColorType bitmapColorType) =>
            bitmapColorType switch
            {
                SKColorType.Rgb565 => RGBLuminanceSource.BitmapFormat.RGB565,
                SKColorType.Rgba8888 => RGBLuminanceSource.BitmapFormat.RGBA32,
                SKColorType.Rgb888x => RGBLuminanceSource.BitmapFormat.RGB24,
                SKColorType.Bgra8888 => RGBLuminanceSource.BitmapFormat.BGR32,
                SKColorType.Gray8 => RGBLuminanceSource.BitmapFormat.Gray8,
                _ => RGBLuminanceSource.BitmapFormat.Unknown
            };

        return results?.Select(GetRawBytes).ToList() ?? [];

        ReadOnlyMemory<byte> GetRawBytes(Result r)
        {
            var segments = (List<byte[]>)r.ResultMetadata[ResultMetadataType.BYTE_SEGMENTS];
            if (segments.Count == 1)
            {
                return segments[0];
            }

            int length = segments.Sum(s => s.Length);
            byte[] total = new byte[length];
            for (int i = 0, s = 0; i < segments.Count; s += segments[i].Length, i++)
            {
                segments[i].CopyTo(total, s);
            }

            return total;
        }
    }
}