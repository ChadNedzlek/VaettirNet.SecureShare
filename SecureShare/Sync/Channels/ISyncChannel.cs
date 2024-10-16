using System.Threading.Tasks;

namespace VaettirNet.SecureShare.Sync.Channels;

public interface ISyncChannel<in TChannelDescriptor>
{
    public static abstract Task<IOpenSyncChannel> Open(TChannelDescriptor descriptor);
}