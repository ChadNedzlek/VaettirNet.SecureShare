namespace VaettirNet.SecureShare;

public delegate TOut SpanFunc<in TIn, out TOut>(TIn span, out int cb)
    where TIn : allows ref struct;