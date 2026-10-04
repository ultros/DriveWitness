using System.Diagnostics;
using DriveWitness.Core;

namespace DriveWitness.App;

internal static class Program
{
    internal static readonly Stopwatch Startup = Stopwatch.StartNew();
    static Program() { } // Suppress beforefieldinit so timing begins before Main, not at first access in Shown.
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        try
        {
            NativeWindows.RequireWindows11();
            string? selfTest = null;
            string? initialDatabase = null;
            bool explorerTest = false;
            if (args.Length > 0)
            {
                if (args.Length == 2 && args[0] == "--self-test") selfTest = Path.GetFullPath(args[1]);
                else if (args.Length == 2 && args[0] == "--explore") initialDatabase = Path.GetFullPath(args[1]);
                else if (args.Length == 3 && args[0] == "--self-test-explorer") { initialDatabase = Path.GetFullPath(args[1]); selfTest = Path.GetFullPath(args[2]); explorerTest = true; }
                else { MessageBox.Show("Open DriveWitness without arguments, or use --explore evidence.db. For automation, use drivewitness-cli.exe.\nGUI test: DriveWitness.exe --self-test report.json", "DriveWitness"); return; }
            }
            Application.Run(new MainForm(selfTest, initialDatabase, explorerTest));
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "DriveWitness", MessageBoxButtons.OK, MessageBoxIcon.Error); Environment.ExitCode = 1; }
    }
}
