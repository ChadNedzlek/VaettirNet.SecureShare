namespace VaettirNet.Cryptography;

/// <summary>
///     Specifies the scope of the data protection to be applied by the
///     <see cref="M:System.Security.Cryptography.ProtectedData.Protect(System.Byte[],System.Byte[],System.Security.Cryptography.DataProtectionScope)" />
///     method.
/// </summary>
public enum DataProtectionScope
{
    /// <summary>The protected data is associated with the current user. Only threads running under the current user context can unprotect the data.</summary>
    CurrentUser,

    /// <summary>
    ///     The protected data is associated with the machine context. Any process running on the computer can unprotect data. This enumeration value is
    ///     usually used in server-specific applications that run on a server where untrusted users are not allowed access.
    /// </summary>
    LocalMachine
}