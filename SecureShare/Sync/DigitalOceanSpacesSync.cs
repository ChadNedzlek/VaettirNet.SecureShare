using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Amazon.S3;
using Amazon.S3.Model;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare.Sync;

public interface IVaultSyncClient
{
    Task<Signed<VaultDataSnapshot>> DownloadVaultAsync(CancellationToken cancellationToken);
    Task UploadVaultAsync(Signed<VaultDataSnapshot> snapshot, CancellationToken cancellationToken);
}

public class DigitalOceanSpacesSync : IVaultSyncClient
{
    private readonly string _bucket;
    private readonly string _region;
    private readonly string _name;
    private readonly string _accessKey;
    private readonly string _secretKey;
    private readonly VaultSnapshotSerializer _serializer;

    private string? _lastEtag;

    public DigitalOceanSpacesSync(string bucket, string region, string name, string accessKey, string secretKey, VaultSnapshotSerializer serializer)
    {
        _bucket = bucket;
        _region = region;
        _name = name;
        _accessKey = accessKey;
        _secretKey = secretKey;
        _serializer = serializer;
    }

    public async Task<Signed<VaultDataSnapshot>> DownloadVaultAsync(CancellationToken cancellationToken)
    {
        AmazonS3Client client = new(_accessKey, _secretKey, new AmazonS3Config { ServiceURL = $"https://{_region}.digitaloceanspaces.com" });
        GetObjectResponse? response = await client.GetObjectAsync(_bucket, _name, cancellationToken);
        if (response == null)
        {
            throw new InvalidOperationException("Failed to download vault");
        }

        _lastEtag = response.ETag;
        Signed<VaultDataSnapshot> snapshot = _serializer.Deserialize(response.ResponseStream);

        ValidateSnapshot(snapshot);

        return snapshot;
    }

    private void ValidateSnapshot(Signed<VaultDataSnapshot> snapshot)
    {
    }

    public async Task UploadVaultAsync(Signed<VaultDataSnapshot> snapshot, CancellationToken cancellationToken)
    {
        var fileName = Path.GetTempFileName();
        await using FileStream tempFileStream = File.Create(Path.GetTempFileName(), 1000, FileOptions.DeleteOnClose);
        _serializer.Serialize(tempFileStream, snapshot);
        await tempFileStream.FlushAsync(cancellationToken);
        tempFileStream.Seek(0, SeekOrigin.Begin);
        AmazonS3Client client = new(_accessKey, _secretKey, new AmazonS3Config { ServiceURL = $"https://{_region}.digitaloceanspaces.com" });
        PutObjectResponse? response = await client.PutObjectAsync(
            new PutObjectRequest { BucketName = _bucket, Key = _name, IfNoneMatch = _lastEtag ?? "*", InputStream = tempFileStream},
            cancellationToken
        );
        
        if (response == null)
        {
            throw new InvalidOperationException("Failed to download vault");
        }
        _lastEtag = response.ETag;
    }
}