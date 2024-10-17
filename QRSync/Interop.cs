using System.Drawing;
using System.Runtime.InteropServices;

namespace QrSync;

internal static partial class Interop
{
    internal static class SystemMetric 
    {
        public const int VirtualScreenX = 76;
        public const int VirtualScreenY = 77;
        public const int VirtualScreenWidth = 78;
        public const int VirtualScreenHeight = 79;
    }

    internal static partial class Monitors
    {
        [LibraryImport("user32.dll")]
        private static partial int GetSystemMetrics(int metric);
        
        public static Rectangle GetVirtualScreenBounds()
        {
            return new Rectangle(
                GetSystemMetrics(SystemMetric.VirtualScreenX),
                GetSystemMetrics(SystemMetric.VirtualScreenY),
                GetSystemMetrics(SystemMetric.VirtualScreenWidth),
                GetSystemMetrics(SystemMetric.VirtualScreenHeight)
            );
        }
    }
}