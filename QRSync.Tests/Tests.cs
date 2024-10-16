using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Numerics;
using System.Reflection;
using System.Runtime.Versioning;
using FluentAssertions;
using FluentAssertions.Formatting;

namespace QrSync.Tests;

public class Tests
{
    [Test]
    [SupportedOSPlatform("windows")]
    public void ReadKnownEmbeddedQrCode()
    {
        using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("QRSync.Tests.Resources.qrcode.png")!;
        IReadOnlyList<ReadOnlyMemory<byte>> res = QrCodeReader.GetCodesFromImage(stream);
        ReadOnlyMemory<byte> bytes = res.Should().ContainSingle().Subject;
        string base64Content = Convert.ToBase64String(bytes.Span);
        base64Content.Should().Be("AQIDBAUGZA==");
    }
    
    [Test]
    [SupportedOSPlatform("windows")]
    public void WriteValue()
    {
        ReadOnlySpan<byte> bytes = [1, 2, 3, 4, 5, 6, 100];
        string inputStr = Convert.ToBase64String(bytes);
        Span<byte> qrCode = stackalloc byte[1000];
        QrCodeWriter.TryWritePng(bytes, qrCode, out int cb).Should().BeTrue();
        IReadOnlyList<ReadOnlyMemory<byte>> codes = QrCodeReader.GetCodesFromImage(qrCode[..cb]);
        ReadOnlyMemory<byte> roundTrip = codes.Should().ContainSingle().Subject;
        string roundTripBase64 = Convert.ToBase64String(roundTrip.Span);
        roundTripBase64.Should().Be(inputStr);
    }

    [Test]
    [SupportedOSPlatform("windows")]
    public void OneOff()
    {
        var dest = IPAddress.Parse("10.0.0.101");
        IPNetwork[] net = [IPNetwork.Parse("10.0.0.0/8"), IPNetwork.Parse("172.16.0.0/12"), IPNetwork.Parse("192.168.0.0/16")];
        foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
        {
            foreach (var uni in iface.GetIPProperties().UnicastAddresses)
            {
                if (uni.Address.AddressFamily == AddressFamily.InterNetwork && net.Any(n => n.Contains(uni.Address)))
                {
                    byte[] addressBytes = uni.Address.GetAddressBytes();
                    IPNetwork adapterNetwork =
                        new(new IPAddress(
                                ((new BigInteger(addressBytes, isBigEndian: true) >> uni.PrefixLength) << uni.PrefixLength).ToByteArray(
                                    isBigEndian: true)),
                            uni.PrefixLength);
                    if (adapterNetwork.Contains(dest))
                    {
                    }
                }
            }
        }
    }
}