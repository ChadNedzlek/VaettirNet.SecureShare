using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace VaettirNet.Cryptography;

public static class ProtectedData
{
    private const int E_FILENOTFOUND = -2147024894;
    private const int ERROR_FILE_NOT_FOUND = 2;
    private static readonly byte[] s_nonEmpty = new byte[1];

    public static byte[] Protect(byte[] userData, byte[]? optionalEntropy, DataProtectionScope scope)
    {
        CheckPlatformSupport();

        if (userData is null)
            throw new ArgumentNullException(nameof(userData));

        TryProtectOrUnprotect(userData, optionalEntropy, default, scope, true, true, out byte[]? buffer, out _);
        return buffer!;
    }

    public static byte[] Unprotect(byte[] encryptedData, byte[]? optionalEntropy, DataProtectionScope scope)
    {
        CheckPlatformSupport();

        if (encryptedData is null)
            throw new ArgumentNullException(nameof(encryptedData));

        TryProtectOrUnprotect(encryptedData, optionalEntropy, default, scope, false, true, out byte[]? buffer, out _);
        return buffer!;
    }

    public static bool TryProtect(
        ReadOnlySpan<byte> userData,
        ReadOnlySpan<byte> optionalEntropy,
        Span<byte> encryptedData,
        DataProtectionScope scope,
        out int bytesWritten
    )
    {
        CheckPlatformSupport();

        return TryProtectOrUnprotect(userData, optionalEntropy, encryptedData, scope, true, false, out _, out bytesWritten);
    }

    public static bool TryUnprotect(
        ReadOnlySpan<byte> encryptedData,
        ReadOnlySpan<byte> optionalEntropy,
        Span<byte> userData,
        DataProtectionScope scope,
        out int bytesWritten
    )
    {
        CheckPlatformSupport();

        return TryProtectOrUnprotect(encryptedData, optionalEntropy, userData, scope, false, false, out _, out bytesWritten);
    }

    public static void Protect(
        ReadOnlySpan<byte> userData,
        ReadOnlySpan<byte> optionalEntropy,
        Span<byte> encryptedData,
        DataProtectionScope scope,
        out int bytesWritten
    )
    {
        CheckPlatformSupport();

        if (!TryProtectOrUnprotect(userData, optionalEntropy, encryptedData, scope, true, false, out _, out bytesWritten))
            throw new ArgumentOutOfRangeException(nameof(encryptedData));
    }

    public static void Unprotect(
        ReadOnlySpan<byte> encryptedData,
        ReadOnlySpan<byte> optionalEntropy,
        Span<byte> userData,
        DataProtectionScope scope,
        out int bytesWritten
    )
    {
        CheckPlatformSupport();

        if (!TryProtectOrUnprotect(encryptedData, optionalEntropy, userData, scope, false, false, out _, out bytesWritten))
            throw new ArgumentOutOfRangeException(nameof(encryptedData));
    }

    private static bool TryProtectOrUnprotect(
        ReadOnlySpan<byte> inputData,
        ReadOnlySpan<byte> optionalEntropy,
        Span<byte> outputBuffer,
        DataProtectionScope scope,
        bool protect,
        bool allocate,
        out byte[]? newBuffer,
        out int bytesWritten
    )
    {
        unsafe
        {
            // The Win32 API will reject pbData == nullptr, and the fixed statement
            // maps empty arrays to nullptr... so when the input is empty use the address of a
            // different array, but still assign cbData to 0.
            ReadOnlySpan<byte> relevantData = inputData.Length == 0 ? stackalloc byte[1] : inputData;

            fixed (byte* pInputData = relevantData, pOptionalEntropy = optionalEntropy)
            {
                DataBlob userDataBlob = new((IntPtr)pInputData, (uint)inputData.Length);
                DataBlob optionalEntropyBlob = default;
                if (!optionalEntropy.IsEmpty) optionalEntropyBlob = new DataBlob((IntPtr)pOptionalEntropy, (uint)optionalEntropy.Length);

                // For .NET Framework compat, we ignore unknown bits in the "scope" value rather than throwing.
                CryptProtectDataFlags flags = CryptProtectDataFlags.CRYPTPROTECT_UI_FORBIDDEN;
                if (scope == DataProtectionScope.LocalMachine) flags |= CryptProtectDataFlags.CRYPTPROTECT_LOCAL_MACHINE;

                DataBlob outputBlob = default;
                try
                {
                    bool success = protect
                        ? Interop.Crypt32.CryptProtectData(ref userDataBlob,
                            null,
                            ref optionalEntropyBlob,
                            IntPtr.Zero,
                            IntPtr.Zero,
                            flags,
                            out outputBlob)
                        : Interop.Crypt32.CryptUnprotectData(ref userDataBlob,
                            IntPtr.Zero,
                            ref optionalEntropyBlob,
                            IntPtr.Zero,
                            IntPtr.Zero,
                            flags,
                            out outputBlob);
                    if (!success)
                    {
                        int lastWin32Error = Marshal.GetLastPInvokeError();
                        if (protect && ErrorMayBeCausedByUnloadedProfile(lastWin32Error))
                            throw new CryptographicException("Profile not loaded");
                        else
                            throw new CryptographicException(lastWin32Error);
                    }

                    // In some cases, the API would fail due to OOM but simply return a null pointer.
                    if (outputBlob.PbData == IntPtr.Zero)
                        throw new OutOfMemoryException();

                    bytesWritten = (int)outputBlob.CbData;

                    if (allocate)
                    {
                        newBuffer = new byte[bytesWritten];
                        Marshal.Copy(outputBlob.PbData, newBuffer, 0, bytesWritten);
                        return true;
                    }
                    else if (bytesWritten > outputBuffer.Length)
                    {
                        newBuffer = null;
                        return false;
                    }
                    else
                    {
                        new Span<byte>(outputBlob.PbData.ToPointer(), (int)outputBlob.CbData).CopyTo(outputBuffer);
                        newBuffer = null;
                        return true;
                    }
                }
                finally
                {
                    if (outputBlob.PbData != IntPtr.Zero)
                    {
                        int length = (int)outputBlob.CbData;
                        byte* pOutputData = (byte*)outputBlob.PbData;
                        for (int i = 0; i < length; i++) pOutputData[i] = 0;
                        Marshal.FreeHGlobal(outputBlob.PbData);
                    }
                }
            }
        }
    }

    // Determine if an error code may have been caused by trying to do a crypto operation while the
    // current user's profile is not yet loaded.
    private static bool ErrorMayBeCausedByUnloadedProfile(int errorCode)
    {
        // CAPI returns a file not found error if the user profile is not yet loaded
        return errorCode is E_FILENOTFOUND or ERROR_FILE_NOT_FOUND;
    }

    private static void CheckPlatformSupport()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) throw new PlatformNotSupportedException();
    }
}