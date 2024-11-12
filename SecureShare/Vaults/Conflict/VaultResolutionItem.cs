namespace VaettirNet.SecureShare.Vaults.Conflict;

public class VaultResolutionItem
{
    public string Name { get; }
    
    public static readonly VaultResolutionItem AcceptLocal = new(nameof(AcceptLocal));
    public static readonly VaultResolutionItem AcceptRemote = new(nameof(AcceptRemote));

    protected VaultResolutionItem(string name)
    {
        Name = name;
    }
}