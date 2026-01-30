# Goida - DLL Injector & Launcher

A professional DLL injector with automatic update system for Windows applications, created in a humorous style.

## What it does

This launcher automatically:
- ✅ Checks for updates on GitHub releases
- ✅ Downloads the latest `Release.rar` archive
- ✅ Extracts `Cheat.dll` using embedded unrar.exe
- ✅ Finds the game executable from Windows registry
- ✅ Launches the game in suspended state
- ✅ Injects the DLL using manual mapping technique
- ✅ Sets working directory for DLL configuration files

## Software

This launcher downloads and injects **Alya-Endfield** cheat software by [@0xCiel](https://github.com/0xCiel/Alya-Endfield).

**Note**: This is a launcher/injector tool. The actual cheat software is developed and maintained by the original author.

## Features

- **Manual DLL Mapping** - Advanced injection without using `LoadLibrary`
- **Automatic Updates** - Checks GitHub releases and downloads latest version
- **Self-contained** - Embedded unrar.exe, no external dependencies
- **Modern Console UI** - Beautiful banner with colored output
- **Version Caching** - Skips re-download if DLL is already up-to-date

## Disclaimer

This launcher is created **in a humorous/joke style** for educational purposes. The tool demonstrates:
- Manual DLL mapping techniques
- Process manipulation
- GitHub API integration
- Archive extraction

**Use at your own risk.** This software is provided "as is" without any warranties.

## Building

1. Open `Goida.sln` in Visual Studio 2019 or later
2. Select `Release|x64` configuration
3. Build the solution (F7)
4. Executable will be in `x64/Release/Goida.exe`

## Requirements

- Windows 10/11 (x64)
- Visual Studio 2019+ with C++ desktop development workload
- Administrator privileges (required for DLL injection)

## Project Structure

```
Goida/
├── include/
│   ├── core/
│   │   └── injector.hxx      # Core injection logic
│   └── utils/
│       ├── archive.hxx       # Archive extraction
│       ├── github.hxx        # GitHub API client
│       ├── paths.hxx         # Path utilities
│       └── unrarbyte.hxx     # Embedded unrar.exe
├── src/
│   ├── core/
│   │   └── injector.cxx       # Manual DLL mapping
│   ├── main.cxx               # Entry point & UI
│   └── utils/
│       ├── archive.cxx        # RAR extraction
│       ├── github.cxx         # GitHub API
│       ├── paths.cxx          # Path management
│       └── unrarbyte.cxx      # Embedded unrar data
└── Goida.vcxproj
```

## License

**Copyright** (MIT License)

```
DesirePro: Free and open-source (FOSS) cheat for RUST.
Copyright (c) 2023 DesirePro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

**Remember**: This is a joke/humorous project. Don't take it too seriously!
