using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Reflection;
using System.Runtime.Versioning;
using FluentAssertions;

namespace QrSync.Tests;

public class Tests
{
    [Test]
    [SupportedOSPlatform("windows")]
    public void ReadKnownEmbeddedQrCode()
    {
        using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("QRSync.Tests.Resources.qrcode.png");
        IEnumerable<ImmutableArray<byte>> res = QrCodeReader.GetCodesFromImageStream(stream);
        ImmutableArray<byte> bytes = res.Should().ContainSingle().Subject;
        string base64Content = Convert.ToBase64String(bytes.AsSpan());
        base64Content.Should().Be("caQTaHR0cHM6Ly90YXJnZXQudGVzdADsEewR7BHsEewR7A==");
    }
}