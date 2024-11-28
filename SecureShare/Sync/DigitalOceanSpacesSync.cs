using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Options;
using VaettirNet.SecureShare.Crypto;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare.Sync;

public record class GetVaultResult(bool FromCache, string CacheKey, Signed<UnvalidatedVaultDataSnapshot> Snapshot);
public record class PutVaultResult(bool Succeeded, string CacheKey, Signed<UnvalidatedVaultDataSnapshot> ConflictVault = null, InvalidVaultException InvalidExistingVault = null);

public class DigitalOceanConfig
{
    public DigitalOceanConfig(string bucket, string region, string name, string accessKey, string secretKey)
    {
        Bucket = bucket;
        Region = region;
        Name = name;
        AccessKey = accessKey;
        SecretKey = secretKey;
    }

    public string Bucket { get; private set; }
    public string Region { get; private set; }
    public string Name { get; private set; }
    public string AccessKey { get; private set; }
    public string SecretKey { get; private set; }
}

public sealed class DigitalOceanSpacesSync : IVaultSyncClient, IDisposable
{
    private readonly VaultSnapshotSerializer _serializer;
    private readonly DigitalOceanConfig _config;
    private readonly IOptionsMonitor<DigitalOceanConfig> _configMonitor;
    private readonly IDisposable _changeRegistration;

    private string _lastEtag;
    private Signed<UnvalidatedVaultDataSnapshot> _lastSnapshot;

    private readonly Lock _clientLock = new();
    private AmazonS3Client _client;

    public DigitalOceanSpacesSync(DigitalOceanConfig digitalOceanConfig, VaultSnapshotSerializer serializer)
    {
        _config = digitalOceanConfig;
        _serializer = serializer;
    }

    public DigitalOceanSpacesSync(IOptionsMonitor<DigitalOceanConfig> digitalOceanConfig, VaultSnapshotSerializer serializer)
    {
        _changeRegistration = digitalOceanConfig.OnChange(ResetClient);
        _configMonitor = digitalOceanConfig;
        _serializer = serializer;
    }

    private void ResetClient(DigitalOceanConfig config, string arg2)
    {
        lock (_clientLock)
        {
            AmazonS3Client newClient = new(config.AccessKey, config.SecretKey, new AmazonS3Config { ServiceURL = $"https://{config.Region}.digitaloceanspaces.com" });
            Volatile.Write(ref _client, newClient);
        }
    }

    public void InitializeCache(string cacheKey, Signed<UnvalidatedVaultDataSnapshot> snapshot)
    {
        _lastEtag = cacheKey;
        _lastSnapshot = snapshot;
    }

    public AmazonS3Client GetClient()
    {
        if (_client != null)
            return _client;
        lock (_clientLock)
        {
            if (_client != null)
                return _client;

            DigitalOceanConfig config = Config;
            AmazonS3Client newClient = new(config.AccessKey, config.SecretKey, new AmazonS3Config { ServiceURL = $"https://{config.Region}.digitaloceanspaces.com" });
            Volatile.Write(ref _client, newClient);
            return newClient;
        }
    }

    private DigitalOceanConfig Config => _configMonitor?.CurrentValue ?? _config!;

    public async Task<GetVaultResult> GetVaultAsync(CancellationToken cancellationToken)
    {
        DigitalOceanConfig config = Config;
        GetObjectResponse response;
        try
        {
            response = await GetClient().GetObjectAsync(
                new GetObjectRequest { BucketName = config.Bucket, Key = config.Name, EtagToNotMatch = _lastEtag },
                cancellationToken
            );
        }
        catch (AmazonS3Exception e) when (e.StatusCode == HttpStatusCode.NotModified)
        {
            return new GetVaultResult(true, _lastEtag!, _lastSnapshot!);
        }

        if (response == null)
        {
            throw new InvalidOperationException("Failed to download vault");
        }
        Signed<UnvalidatedVaultDataSnapshot> snapshot = _serializer.Deserialize(response.ResponseStream);

        _lastEtag = response.ETag;
        _lastSnapshot = snapshot;
        return new GetVaultResult(false, response.ETag, snapshot);
    }

    public async Task<PutVaultResult> PutVaultAsync(ValidatedVaultDataSnapshot snapshot, string etag, bool force, CancellationToken cancellationToken)
    {
        etag ??= _lastEtag;
        DigitalOceanConfig config = Config;
        await using FileStream tempFileStream = File.Create(Path.GetTempFileName(), 1000, FileOptions.DeleteOnClose);
        _serializer.Serialize(tempFileStream, snapshot);
        await tempFileStream.FlushAsync(cancellationToken);
        tempFileStream.Seek(0, SeekOrigin.Begin);
        try
        {
            PutObjectRequest request = new() { BucketName = config.Bucket, Key = config.Name, InputStream = tempFileStream };
            if (!force)
            {
                request.IfNoneMatch = etag ?? "*";
            }

            PutObjectResponse response = await GetClient()
                .PutObjectAsync(
                    request,
                    cancellationToken
                );

            if (response == null)
            {
                throw new InvalidOperationException("Failed to download vault");
            }

            _lastEtag = response.ETag;
            return new PutVaultResult(true, response.ETag);
        }
        catch (AmazonS3Exception exception) when (exception.StatusCode == HttpStatusCode.PreconditionFailed)
        {
            GetObjectResponse response = await GetClient()
                .GetObjectAsync(
                    new GetObjectRequest { BucketName = config.Bucket, Key = config.Name, EtagToNotMatch = _lastEtag },
                    cancellationToken
                );
            Signed<UnvalidatedVaultDataSnapshot> redownloadFresh = _serializer.Deserialize(response.ResponseStream);
            try
            {
            }
            catch (InvalidVaultException ex)
            {
                return new PutVaultResult(false, response.ETag, InvalidExistingVault: ex);
            }

            return new PutVaultResult(false, response.ETag, ConflictVault: redownloadFresh);
        }
    }

    public void Dispose()
    {
        _changeRegistration?.Dispose();
        _client?.Dispose();
    }
}