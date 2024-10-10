using System;
using System.Runtime.InteropServices;

namespace VaettirNet.Cryptography;

internal static partial class Interop
{
    internal static partial class Crypt32
    {
        [LibraryImport("crypt32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool CryptProtectData(
            in DataBlob pDataIn,
            string? szDataDescr,
            ref DataBlob pOptionalEntropy,
            IntPtr pvReserved,
            IntPtr pPromptStruct,
            CryptProtectDataFlags dwFlags,
            out DataBlob pDataOut
        );

        [LibraryImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool CryptUnprotectData(
            in DataBlob pDataIn,
            IntPtr ppszDataDescr,
            ref DataBlob pOptionalEntropy,
            IntPtr pvReserved,
            IntPtr pPromptStruct,
            CryptProtectDataFlags dwFlags,
            out DataBlob pDataOut
        );
    }
}