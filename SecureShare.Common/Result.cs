using System;
using System.Diagnostics.CodeAnalysis;

namespace VaettirNet.SecureShare.Common;

public readonly struct Result<T>
{
    public static readonly Result<T> Failed = default;
    private readonly T _value;
    
    public bool IsSuccess { get; }

    public Result(T value)
    {
        _value = value;
        IsSuccess = true;
    }

    public T GetValue()
    {
        if (IsSuccess) throw new InvalidOperationException("Result is not set");
        return _value;
    }

    public bool TryGetValue(out T value)
    {
        value = _value;
        return IsSuccess;
    }

    public T GetValueOrDefault(T defaultValue = default!)
    {
        return IsSuccess ? _value : defaultValue;
    }

    public Result<TOther> Map<TOther>(Func<T, TOther> map)
    {
        return IsSuccess ? new Result<TOther>(map(_value!)) : default;
    }
}

public readonly struct Result<T, TError>
{
    private readonly T? _value;
    private readonly TError? _error;
    public bool IsSuccess { get; }

    public Result(T item)
    {
        _value = item;
        IsSuccess = true;
    }

    public Result(TError item)
    {
        _error = item;
    }

    public void Map(Action<T> valueAction, Action<TError> errorAction)
    {
        if (IsSuccess) valueAction(_value!);
        else errorAction(_error!);
    }

    public TOther Map<TOther>(Func<T, TOther> valueMap, Func<TError, TOther> errorMap)
    {
        return IsSuccess ? valueMap(_value!) : errorMap(_error!);
    }

    public Result<TA, TB> Map<TA, TB>(Func<T, TA> valueMap, Func<TError, TB> errorMap)
    {
        return IsSuccess ? new(valueMap(_value!)) : new(errorMap(_error!));
    }

    public Result<TA, TError> Map<TA>(Func<T, TA> map)
    {
        return IsSuccess ? new(map(_value!)) : new Result<TA, TError>(_error!);
    }

    public static implicit operator Result<T, TError>(T item) => new(item);
    public static implicit operator Result<T, TError>(TError item) => new(item);

    public bool TryGetValue([NotNullWhen(true)] out T value)
    {
        if (IsSuccess)
        {
            value = _value!;
            return true;
        }

        value = default!;
        return false;
    }
}