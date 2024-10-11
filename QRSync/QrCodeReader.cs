using System.Collections.Generic;
using System.Collections.Immutable;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ZXing;
using ZXing.Common;
using ZXing.Multi.QrCode;

namespace QrSync;

public class QrCodeReader
{
    [SupportedOSPlatform("windows")]
    public static IEnumerable<ImmutableArray<byte>> GetCodesFromScreen()
    {
        Rectangle bounds = Interop.Monitors.GetVirtualScreenBounds();
        using Bitmap bitmap = new(bounds.Width, bounds.Height);
        using Graphics g = Graphics.FromImage(bitmap);
        g.CopyFromScreen(bounds.X, bounds.Y, 0, 0, bitmap.Size);

        return GetCodesFromBitmap(bitmap);
    }
    
    [SupportedOSPlatform("windows")]
    public static IEnumerable<ImmutableArray<byte>> GetCodesFromImageFile(string filename)
    {
        using Bitmap bitmap = new(filename);
        return GetCodesFromBitmap(bitmap);
    }
    
    [SupportedOSPlatform("windows")]
    public static IEnumerable<ImmutableArray<byte>> GetCodesFromImageStream(Stream stream)
    {
        using Bitmap bitmap = new(stream);
        return GetCodesFromBitmap(bitmap);
    }

    [SupportedOSPlatform("windows")]
    private static IEnumerable<ImmutableArray<byte>> GetCodesFromBitmap(Bitmap bitmap)
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
        return results?.Select(r => r.RawBytes.ToImmutableArray()).ToList() ?? [];
    }
}