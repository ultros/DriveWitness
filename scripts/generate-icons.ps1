$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -eq 'Core') {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
    if ($LASTEXITCODE -ne 0) { throw 'Icon rendering failed.' }
    return
}
$assetDirectory = Join-Path (Split-Path -Parent $PSScriptRoot) 'src/DriveWitness.App/Assets'
New-Item -ItemType Directory -Force -Path $assetDirectory | Out-Null
Add-Type -AssemblyName System.Drawing
Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @'
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
public static class DriveWitnessIconRenderer {
  public static void Render(int size, string output) {
    using (var image = new Bitmap(size,size)) using (var g = Graphics.FromImage(image)) {
      g.SmoothingMode = SmoothingMode.AntiAlias; g.Clear(Color.Transparent);
      g.ScaleTransform(size/512f,size/512f);
      using (var shield = new GraphicsPath()) {
        shield.AddLines(new PointF[]{new PointF(256,30),new PointF(442,100),new PointF(430,278)});
        shield.AddBezier(430,278,417,377,345,442,256,484);
        shield.AddBezier(256,484,167,442,95,377,82,278);
        shield.AddLine(82,278,70,100); shield.CloseFigure();
        using(var fill=new SolidBrush(Color.FromArgb(16,31,52))) g.FillPath(fill,shield);
        using(var edge=new Pen(Color.FromArgb(225,238,255),size<=24?28:18)) g.DrawPath(edge,shield);
      }
      using(var drive=new GraphicsPath()) {
        drive.AddLines(new PointF[]{new PointF(165,164),new PointF(347,164),new PointF(366,330),new PointF(146,330)}); drive.CloseFigure();
        using(var fill=new SolidBrush(Color.FromArgb(35,126,245))) g.FillPath(fill,drive);
        using(var edge=new Pen(Color.FromArgb(170,206,255),10)) g.DrawPath(edge,drive);
      }
      using(var platter=new SolidBrush(Color.FromArgb(12,25,44))) g.FillEllipse(platter,203,198,106,106);
      using(var ring=new Pen(Color.FromArgb(223,238,255),12)) g.DrawEllipse(ring,203,198,106,106);
      using(var hub=new SolidBrush(Color.FromArgb(223,238,255))) g.FillEllipse(hub,244,239,24,24);
      using(var slot=new Pen(Color.FromArgb(223,238,255),size<=24?14:9)) g.DrawLine(slot,172,348,340,348);
      image.Save(output,ImageFormat.Png);
    }
  }
}
'@
$iconSizes = @(16,24,32,48,64,128,256)
foreach ($iconSize in ($iconSizes + 512)) { [DriveWitnessIconRenderer]::Render($iconSize, (Join-Path $assetDirectory "drivewitness-$iconSize.png")) }
$stream = [IO.File]::Create((Join-Path $assetDirectory 'drivewitness.ico'))
$writer = [IO.BinaryWriter]::new($stream)
try {
    $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$iconSizes.Count)
    $offset = 6 + 16 * $iconSizes.Count
    $images = @()
    foreach ($iconSize in $iconSizes) {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $assetDirectory "drivewitness-$iconSize.png")); $images += ,$bytes
        $dimension = if ($iconSize -eq 256) { 0 } else { $iconSize }
        $writer.Write([byte]$dimension); $writer.Write([byte]$dimension); $writer.Write([byte]0); $writer.Write([byte]0)
        $writer.Write([uint16]1); $writer.Write([uint16]32); $writer.Write([uint32]$bytes.Length); $writer.Write([uint32]$offset); $offset += $bytes.Length
    }
    foreach ($bytes in $images) { $writer.Write([byte[]]$bytes) }
} finally { $writer.Dispose(); $stream.Dispose() }
