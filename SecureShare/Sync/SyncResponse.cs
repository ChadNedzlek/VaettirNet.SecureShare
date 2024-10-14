using System;
using System.Collections.Immutable;
using VaettirNet.SecureShare.Sync.Descriptors;

namespace VaettirNet.SecureShare.Sync;

public record SyncResponse(ReadOnlyMemory<byte> PublicKey, ReadOnlyMemory<byte> SyncKey, ImmutableArray<SyncChannelDescriptor> SupportedChannels);