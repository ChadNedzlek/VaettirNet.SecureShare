namespace VaettirNet.SecureShare;

public readonly ref struct RefTuple<T1, T2> where T1 : allows ref struct where T2: allows ref struct
{
    public readonly T1 Item1;
    public readonly T2 Item2;

    public RefTuple(T1 item1, T2 item2)
    {
        Item1 = item1;
        Item2 = item2;
    }

    public void Deconstruct(out T1 span1, out T2 span2)
    {
        span1 = Item1;
        span2 = Item2;
    }
}