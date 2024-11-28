namespace VaettirNet.SecureShare.Common;

public delegate TOut SpanStateFunc<in TIn, in TState, out TOut>(TIn span, TState state, out int cb)
    where TState : allows ref struct
    where TIn : allows ref struct;