using System;
using System.Runtime.InteropServices;

namespace VaettirNet.Cryptography;

[StructLayout(LayoutKind.Sequential)]
internal struct DataBlob
{
    internal uint CbData;
    internal IntPtr PbData;

    internal DataBlob(IntPtr handle, uint size)
    {
        CbData = size;
        PbData = handle;
    }
}