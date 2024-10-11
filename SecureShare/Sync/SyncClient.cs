using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using VaettirNet.Threading.Tasks;

namespace VaettirNet.SecureShare.Sync;

public abstract class SyncClient
{
}

public abstract class SyncChannelHandler
{
    public abstract ChannelType SupportedType { get; }
    public abstract ICovariantTask<SyncChannel> OpenAsync(SyncChannelDescriptor descriptor);
}

public abstract class SyncChannelHandler<TChannel, TChannelDescriptor> : SyncChannelHandler where TChannel : SyncChannel<TChannelDescriptor>, ISyncChannel<TChannel, TChannelDescriptor>
    where TChannelDescriptor : SyncChannelDescriptor
{
    public sealed override ICovariantTask<TChannel> OpenAsync(SyncChannelDescriptor descriptor) => TChannel.Open((TChannelDescriptor)descriptor);
}

public interface ISyncChannel<out TChannel, in TChannelDescriptor>
{
    public static abstract ICovariantTask<TChannel> Open(TChannelDescriptor descriptor);
}

public class FileSyncChannel : SyncChannel<FileSyncChannelDescriptor>, ISyncChannel<FileSyncChannel, FileSyncChannelDescriptor>
{
    private readonly FileSyncChannelDescriptor _descriptor;

    private FileSyncChannel(FileSyncChannelDescriptor descriptor)
    {
        _descriptor = descriptor;
    }

    public static ICovariantTask<FileSyncChannel> Open(FileSyncChannelDescriptor descriptor)
        => CovariantTask.FromResult(new FileSyncChannel(descriptor));
}


public class SyncChannel
{
}

public class SyncChannel<TChannelDescriptor> : SyncChannel where TChannelDescriptor : SyncChannelDescriptor
{
}

public record SyncRequest(Guid ClientId, string Description, ImmutableArray<byte> PublicKey, ImmutableArray<SyncChannelDescriptor> SupportedChannels);

public enum ChannelType
{
    None = 0,
    File,
    Tcp,
    Inline
}

public abstract class SyncChannelDescriptor
{
    [JsonIgnore]
    public abstract bool IsPersistentChannel { get; }
    [JsonIgnore]
    public abstract bool IsOfflineAccessible { get; }

    public abstract ChannelType ChannelType { get; }
}

public class FileSyncChannelDescriptor : SyncChannelDescriptor
{
    [JsonIgnore]
    public override bool IsPersistentChannel => true;
    [JsonIgnore]
    public override bool IsOfflineAccessible => true;
    
    public override ChannelType ChannelType => ChannelType.File;

    public string Path { get; }
    
    public FileSyncChannelDescriptor(string path)
    {
        Path = path;
    }
}

public class TcpSyncChannelDescriptor : SyncChannelDescriptor
{
    [JsonIgnore]
    public override bool IsPersistentChannel => false;
    [JsonIgnore]
    public override bool IsOfflineAccessible => false;
    public override ChannelType ChannelType => ChannelType.Tcp;

    public string Host { get; }
    public int Port { get; }

    public TcpSyncChannelDescriptor(string host, int port)
    {
        Host = host;
        Port = port;
    }
}

public class InlineSyncChannelDescriptor : SyncChannelDescriptor
{
    [JsonIgnore]
    public override bool IsPersistentChannel => false;
    [JsonIgnore]
    public override bool IsOfflineAccessible => false;
    
    public override ChannelType ChannelType => ChannelType.Inline;

    public string Vault { get; }

    public InlineSyncChannelDescriptor(string vault)
    {
        Vault = vault;
    }
}

public record SyncResponse(ImmutableArray<byte> PublicKey, ImmutableArray<byte> SyncKey, ImmutableArray<SyncChannelDescriptor> SupportedChannels);