using System;
using System.Collections.Immutable;
using VaettirNet.SecureShare.Sync.Descriptors;

namespace VaettirNet.SecureShare.Sync;

public record SyncRequest(Guid ClientId, string Description, ReadOnlyMemory<byte> PublicKey, ImmutableArray<SyncChannelDescriptor> SupportedChannels);