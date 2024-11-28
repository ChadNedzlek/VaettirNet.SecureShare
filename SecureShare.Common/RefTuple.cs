namespace VaettirNet.SecureShare.Common;

public readonly ref struct RefTuple<T1, T2, T3>
    where T1 : allows ref struct
    where T2: allows ref struct
    where T3: allows ref struct
{
    public readonly T1 Item1;
    public readonly T2 Item2;
    public readonly T3 Item3;

    public RefTuple(T1 item1, T2 item2, T3 item3)
    {
        Item1 = item1;
        Item2 = item2;
        Item3 = item3;
    }

    public void Deconstruct(out T1 item1, out T2 item2, out T3 item3)
    {
        item1 = Item1;
        item2 = Item2;
        item3 = Item3;
    }
}

public static class RefTuple
{
    public static RefTuple<T1, T2> Create<T1, T2>(T1 item1, T2 item2)
        where T1 : allows ref struct
        where T2 : allows ref struct
        => new(item1, item2);

    public static RefTuple<T1, T2, T3> Create<T1, T2, T3>(T1 item1, T2 item2, T3 item3)
        where T1 : allows ref struct
        where T2 : allows ref struct
        where T3 : allows ref struct
        => new(item1, item2, item3);
}

public readonly ref struct RefTuple<T1, T2>
    where T1 : allows ref struct
    where T2 : allows ref struct
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