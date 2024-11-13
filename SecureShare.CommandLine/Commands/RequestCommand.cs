using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using QRSync;
using VaettirNet.SecureShare.CommandLine.Services;
using VaettirNet.SecureShare.Serialization;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare.CommandLine.Commands;

[Command("request|r")]
internal class RequestCommand : BaseCommand<RunState>
{
    [Command("create|c")]
    internal class CreateCommand : ChildCommand<RunState, RequestCommand>
    {
        protected override int Execute(RunState state, RequestCommand parent, ImmutableList<string> args)
        {
            VaultRequest request = VaultRequest.Create(args.FirstOrDefault() ?? "request", state.Algorithm.GetPublic(state.Keys));
            IBinarySerializer<VaultRequest> serializer = VaultRequest.GetBinarySerializer();
            using RentedSpan<byte> bytes = SpanHelpers.GrowingSpan(
                stackalloc byte[1000],
                (Span<byte> span, out int cb) => serializer.TrySerialize(request, span, out cb),
                ArrayPool<byte>.Shared
            );
            
            Console.WriteLine(Convert.ToBase64String(bytes.Span));

            QrCodeWriter.WritePng(bytes.Span, @"C:\temp\request.png");
            return 0;
        }
    }
    
    [Command("accept|a")]
    internal class AcceptCommand : ChildCommand<RunState, RequestCommand>
    {
        private readonly CommandPrompt _prompt;

        internal AcceptCommand(CommandPrompt prompt)
        {
            _prompt = prompt;
        }

        protected override int Execute(RunState state, RequestCommand parent, ImmutableList<string> args)
        {
            Span<byte> bytes = stackalloc byte[Base64.GetMaxDecodedFromUtf8Length(args[0].Length)];
            Convert.TryFromBase64String(args[0], bytes, out int cb);
            bytes = bytes[..cb];
            IBinarySerializer<VaultRequest> serializer = VaultRequest.GetBinarySerializer();
            VaultRequest request = serializer.Deserialize(bytes);
            _prompt.WriteLine($"Request for client: {request.ClientId}");
            _prompt.WriteLine($"Description: {request.Description}");
            if (!request.ExtraData.IsEmpty)
            {
                Span<char> characters = stackalloc char[Encoding.UTF8.GetMaxCharCount(request.ExtraData.Length)];
                int len = Encoding.UTF8.GetChars(request.ExtraData.Span, characters);
                _prompt.WriteLine($"Extra data: {characters[..len]}");
            }

            if (!_prompt.Confirm("Approve request? "))
            {
                _prompt.WriteLine("Aborting import");
                return 0;
            }

            state.VaultManager.AddAuthenticatedClient(new RefSigner(state.Algorithm, state.Keys), request);
            _prompt.WriteLine("Client added", ConsoleColor.Cyan);
            return 0;
        }
    }
}