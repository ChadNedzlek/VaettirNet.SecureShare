using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using ProtoBuf;
using ProtoBuf.Meta;

namespace VaettirNet.SecureShare.Serialization;

public class FullObjectSerializer
{
    public static FullObjectSerializer Instance { get; } = new ();

    public static FullObjectSerializer Create<T>()
    {
        IList<CustomAttributeData> attrData = typeof(T).GetCustomAttributesData();
        if (attrData.All(a => a.AttributeType != typeof(ProtoContractAttribute)))
        {
            throw new ArgumentException($"Type {typeof(T).Name} must have [ProtoContract]");
        }

        if (typeof(T).GetConstructor([]) == null)
        {
            throw new ArgumentException($"Type {typeof(T).Name} must have parameterless constructor");
        }

        return Instance;
    }

    public JsonNode Serialize(object value, Type type) => (JsonObject)JsonSerializer.SerializeToNode(value, type)!;
    public object? Deserialize(JsonNode json, Type type) => json.Deserialize(type);
    
    public bool TrySerialize(object value, Type type, Span<byte> destination, out int bytesWritten)
    {
        unsafe
        {
            fixed (byte* buffer = &destination.GetPinnableReference())
            {
                UnmanagedMemoryStream s = new(buffer, 0, destination.Length, FileAccess.Write);
                RuntimeTypeModel.CreateForAssembly(type).Serialize(s, value);
                s.Flush();
                bytesWritten = (int)s.Length;
                return true;
            }
        }
    }

    public object Deserialize(ReadOnlySpan<byte> source, Type type)
    {
        unsafe
        {
            fixed (byte* buffer = &source.GetPinnableReference())
            {
                using PointerMemoryManager<byte> mm = new(buffer, source.Length);
                return RuntimeTypeModel.CreateForAssembly(type).Deserialize(mm.Memory, type:type);
            }
        }
    }
    
    private sealed unsafe class PointerMemoryManager<T> : MemoryManager<T> where T : struct
    {
        private readonly void* _pointer;
        private readonly int _length;

        internal PointerMemoryManager(void* pointer, int length)
        {
            _pointer = pointer;
            _length = length;
        }

        protected override void Dispose(bool disposing)
        {
        }

        public override Span<T> GetSpan()
        {
            return new Span<T>(_pointer, _length);
        }

        public override MemoryHandle Pin(int elementIndex = 0)
        {
            throw new NotSupportedException();
        }

        public override void Unpin()
        {
        }
    }
}