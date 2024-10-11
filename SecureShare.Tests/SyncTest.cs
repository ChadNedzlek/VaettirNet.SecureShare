using System.Text.Json;
using VaettirNet.SecureShare.Sync;

namespace SecureShare.Tests;

public class SyncTests
{
    [Test]
    public void Basic()
    {
        var s = JsonSerializer.Serialize(new FileSyncChannelDescriptor(@"C:\temp\pizza.txt"));
        var descriptor = JsonSerializer.Deserialize<FileSyncChannelDescriptor>(s);
    }
}