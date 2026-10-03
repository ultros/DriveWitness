# Dependencies

DriveWitness includes third-party components under their respective licenses:

- [.NET runtime](https://github.com/dotnet/runtime) and [Windows Forms](https://github.com/dotnet/winforms): MIT. Self-contained runtime distributions supply their third-party notices.
- [Microsoft.Data.Sqlite](https://github.com/dotnet/efcore): MIT.
- [SQLitePCLRaw](https://github.com/ericsink/SQLitePCL.raw): Apache-2.0; [SQLite](https://sqlite.org/copyright.html): public domain.
- [Blake3.Native / Blake3.NET](https://github.com/xoofx/Blake3.NET): wrapper BSD-2-Clause; [official BLAKE3](https://github.com/BLAKE3-team/BLAKE3): Apache-2.0 or CC0-1.0.
- [Bouncy Castle C#](https://github.com/bcgit/bc-csharp): MIT.

License texts and the runtime's third-party notices are included in `licenses/`. The BLAKE3 native implementation is distributed under its CC0 option. Versions/transitive dependencies are pinned in project `packages.lock.json` files. Development-only xUnit/runner and Microsoft.NET.Test.Sdk are not shipped in the application distribution. The retained Python reference has separate dependencies that the C# applications do not require.
