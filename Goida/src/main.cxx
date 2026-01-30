#include "core/injector.hxx"
#include "utils/paths.hxx"
#include "utils/github.hxx"
#include "utils/archive.hxx"
#include <windows.h>
#include <shlwapi.h>
#include <string>
#include <sstream>
#include <algorithm>
#include <cstring>

#pragma comment(lib, "shlwapi.lib")

namespace {
    constexpr int TITLE_LENGTH = 30;
    constexpr int AUTHOR_LENGTH = 40;
    constexpr int AUTO_CLOSE_TIMEOUT_MS = 15000;

    const WORD COLOR_WHITE = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    const WORD COLOR_BLUE = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    const WORD COLOR_RED = FOREGROUND_RED | FOREGROUND_INTENSITY;
    const WORD COLOR_DEFAULT = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED;
}

static void WaitForInputOrTimeout( int timeoutMs ) {
    DWORD startTime = GetTickCount( );
    HANDLE hInput = GetStdHandle( STD_INPUT_HANDLE );

    if ( hInput == INVALID_HANDLE_VALUE ) {
        Sleep( timeoutMs );
        return;
    }

    DWORD consoleMode = 0;
    if ( !GetConsoleMode( hInput, &consoleMode ) ) {
        Sleep( timeoutMs );
        return;
    }

    SetConsoleMode( hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );

    while ( true ) {
        DWORD currentTime = GetTickCount( );
        DWORD elapsed = currentTime - startTime;

        if ( elapsed >= static_cast< DWORD >( timeoutMs ) ) {
            break;
        }

        DWORD numberOfEvents = 0;
        if ( !GetNumberOfConsoleInputEvents( hInput, &numberOfEvents ) ) {
            Sleep( 100 );
            continue;
        }

        if ( numberOfEvents > 0 ) {
            INPUT_RECORD inputRecord;
            DWORD numberOfEventsRead = 0;

            if ( ReadConsoleInputA( hInput, &inputRecord, 1, &numberOfEventsRead ) ) {
                if ( inputRecord.EventType == KEY_EVENT && inputRecord.Event.KeyEvent.bKeyDown ) {
                    break;
                }
            }
        }

        Sleep( 50 );
    }
}

static std::string FormatReleaseNotes( const std::string & body ) {
    std::string cleanedBody = body;
    cleanedBody.erase( std::remove( cleanedBody.begin( ), cleanedBody.end( ), '\r' ), cleanedBody.end( ) );

    std::stringstream ss( cleanedBody );
    std::string line;
    std::string result;

    while ( std::getline( ss, line ) ) {
        if ( line.empty( ) ) {
            continue;
        }

        std::string trimmed = line;
        while ( !trimmed.empty( ) && ( trimmed[ 0 ] == ' ' || trimmed[ 0 ] == '\t' ) ) {
            trimmed.erase( 0, 1 );
        }

        if ( trimmed.empty( ) ) {
            continue;
        }

        if ( trimmed[ 0 ] == '*' || trimmed[ 0 ] == '-' ) {
            result += "  " + trimmed + "\n";
        } else if ( trimmed[ 0 ] != '#' ) {
            result += "  " + trimmed + "\n";
        }
    }

    return result;
}

static void PrintBanner( const GitHubRelease * release = nullptr ) {
    HANDLE hConsole = GetStdHandle( STD_OUTPUT_HANDLE );
    COORD pos = { 0, 0 };
    SetConsoleCursorPosition( hConsole, pos );

    std::string version = release ? release->tag : "v0.0.0";
    std::string releaseNotes = release ? FormatReleaseNotes( release->body ) : "";

    const char * asciiLines[ ] = {
        "────────────────────────────────────────────────────────────────────────",
        "─██████████████─██████████████─██████████─████████████───██████████████─",
        "─██░░░░░░░░░░██─██░░░░░░░░░░██─██░░░░░░██─██░░░░░░░░████─██░░░░░░░░░░██─",
        "─██░░██████████─██░░██████░░██─████░░████─██░░████░░░░██─██░░██████░░██─",
        "─██░░██─────────██░░██──██░░██───██░░██───██░░██──██░░██─██░░██──██░░██─",
        "─██░░██─────────██░░██──██░░██───██░░██───██░░██──██░░██─██░░██████░░██─",
        "─██░░██──██████─██░░██──██░░██───██░░██───██░░██──██░░██─██░░░░░░░░░░██─",
        "─██░░██──██░░██─██░░██──██░░██───██░░██───██░░██──██░░██─██░░██████░░██─",
        "─██░░██──██░░██─██░░██──██░░██───██░░██───██░░██──██░░██─██░░██──██░░██─",
        "─██░░██████░░██─██░░██████░░██─████░░████─██░░████░░░░██─██░░██──██░░██─",
        "─██░░░░░░░░░░██─██░░░░░░░░░░██─██░░░░░░██─██░░░░░░░░████─██░░██──██░░██─",
        "─██████████████─██████████████─██████████─████████████───██████──██████─",
        "────────────────────────────────────────────────────────────────────────"
    };

    printf( "\n" );

    SetConsoleTextAttribute( hConsole, COLOR_WHITE );
    printf( "%s\n", asciiLines[ 0 ] );
    printf( "%s\n", asciiLines[ 1 ] );
    printf( "%s\n", asciiLines[ 2 ] );

    SetConsoleTextAttribute( hConsole, COLOR_BLUE );
    printf( "%s\n", asciiLines[ 3 ] );
    printf( "%s\n", asciiLines[ 4 ] );
    printf( "%s\n", asciiLines[ 5 ] );
    printf( "%s\n", asciiLines[ 6 ] );
    printf( "%s\n", asciiLines[ 7 ] );

    SetConsoleTextAttribute( hConsole, COLOR_RED );
    printf( "%s\n", asciiLines[ 8 ] );
    printf( "%s\n", asciiLines[ 9 ] );
    printf( "%s\n", asciiLines[ 10 ] );
    printf( "%s\n", asciiLines[ 11 ] );

    SetConsoleTextAttribute( hConsole, COLOR_WHITE );
    printf( "%s\n", asciiLines[ 12 ] );

    printf( "\n" );
    printf( "                        G O I D A   L A U N C H E R                        \n" );
    printf( "\n" );
    printf( "                                Version: %s                                \n", version.c_str( ) );
    printf( "  ────────────────────────────────────────────────────────────────────────  \n" );

    if ( !releaseNotes.empty( ) ) {
        printf( "  Latest changes:                                                               \n" );
        printf( "%s", releaseNotes.c_str( ) );
    }

    printf( "\n" );
    SetConsoleTextAttribute( hConsole, COLOR_RED );
    printf( "                   GOIDA injector   by @desirepro                   \n" );
    printf( "\n" );

    SetConsoleTextAttribute( hConsole, COLOR_DEFAULT );
}

void InjectionThread( const std::string & exePath ) {
    if ( !IsAdmin( ) ) {
        Log( LogLevel::ERROR_LEVEL, "Administrator rights required\n" );
        return;
    }

    if ( IsProcessRunning( "Endfield.exe" ) ) {
        Log( LogLevel::ERROR_LEVEL, "Game is already running\n" );
        return;
    }

    Log( LogLevel::INFO, "Launching game...\n" );
    PROCESS_INFORMATION pi = { 0 };
    if ( !LaunchProcessSuspended( exePath, pi ) ) {
        return;
    }

    EnableDebugPrivilege( );

    if ( !CheckProcessArchitecture( pi.hProcess ) ) {
        CleanupProcess( pi );
        Log( LogLevel::ERROR_LEVEL, "Invalid architecture\n" );
        return;
    }

    std::string dllPath = GetDllPath( );
    if ( GetFileAttributesA( dllPath.c_str( ) ) == INVALID_FILE_ATTRIBUTES ) {
        CleanupProcess( pi );
        Log( LogLevel::ERROR_LEVEL, "DLL not found\n" );
        return;
    }

    Log( LogLevel::INFO, "Injecting DLL...\n" );
    if ( !ManualMapDLL( pi.hProcess, dllPath ) ) {
        CleanupProcess( pi );
        return;
    }

    std::string mainDir = GetMainDirectory( );
    HMODULE hKernel32 = GetModuleHandleA( "kernel32.dll" );
    if ( hKernel32 ) {
        FARPROC pSetCurrentDirectory = GetProcAddress( hKernel32, "SetCurrentDirectoryA" );
        if ( pSetCurrentDirectory ) {
            SIZE_T pathSize = mainDir.length( ) + 1;
            LPVOID pRemotePath = VirtualAllocEx( pi.hProcess, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
            if ( pRemotePath ) {
                if ( WriteProcessMemory( pi.hProcess, pRemotePath, mainDir.c_str( ), pathSize, nullptr ) ) {
                    HANDLE hThread = CreateRemoteThread( pi.hProcess, nullptr, 0,
                        reinterpret_cast< LPTHREAD_START_ROUTINE >( pSetCurrentDirectory ),
                        pRemotePath, 0, nullptr );
                    if ( hThread ) {
                        WaitForSingleObject( hThread, INFINITE );
                        CloseHandle( hThread );
                    }
                }
                VirtualFreeEx( pi.hProcess, pRemotePath, 0, MEM_RELEASE );
            }
        }
    }

    if ( pi.hThread ) {
        if ( ResumeThread( pi.hThread ) == ( DWORD ) -1 ) {
            CleanupProcess( pi );
            Log( LogLevel::ERROR_LEVEL, "Failed to resume thread\n" );
            return;
        }
        CloseHandle( pi.hThread );
        pi.hThread = nullptr;
    }

    CloseHandle( pi.hProcess );
    pi.hProcess = nullptr;
}

static bool CheckAndUpdate( GitHubRelease & release ) {
    Log( LogLevel::INFO, "Checking for updates...\n" );

    std::string mainDir = GetMainDirectory( );
    CreateDirectoryA( mainDir.c_str( ), nullptr );

    if ( !GetLatestRelease( release ) ) {
        Log( LogLevel::WARNING, "Failed to check for updates, continuing with existing DLL\n" );
        return false;
    }

    std::string savedVersion = GetSavedVersion( );
    std::string dllPath = GetDllPath( );

    if ( !savedVersion.empty( ) && savedVersion == release.tag ) {
        if ( GetFileAttributesA( dllPath.c_str( ) ) != INVALID_FILE_ATTRIBUTES ) {
            Log( LogLevel::SUCCESS, "Latest version already installed (%s)\n", release.tag.c_str( ) );
            return true;
        }
    }

    std::string exeDir = GetExecutableDirectory( );
    std::string rarPath = exeDir + "\\Release.rar";

    Log( LogLevel::INFO, "Downloading latest release...\n" );
    if ( !DownloadFile( release.downloadUrl, rarPath ) ) {
        Log( LogLevel::WARNING, "Failed to download update, continuing with existing DLL\n" );
        return false;
    }

    Log( LogLevel::INFO, "Extracting Cheat.dll...\n" );
    if ( !ExtractCheatDllFromRar( rarPath, dllPath ) ) {
        Log( LogLevel::WARNING, "Failed to extract DLL, continuing with existing DLL\n" );
        return false;
    }

    SaveVersion( release.tag );
    Log( LogLevel::SUCCESS, "Update completed successfully!\n" );
    return true;
}

int main( ) {
    InitConsole( );

    srand( static_cast< unsigned int >( GetTickCount( ) ) );

    std::string mainDir = GetMainDirectory( );
    CreateDirectoryA( mainDir.c_str( ), nullptr );

    GitHubRelease release;
    bool hasRelease = GetLatestRelease( release );
    PrintBanner( hasRelease ? &release : nullptr );

    if ( hasRelease ) {
        CheckAndUpdate( release );
    } else {
        Log( LogLevel::WARNING, "Failed to fetch release information\n" );
    }

    std::string exePath = GetGameExePath( );
    if ( exePath.empty( ) ) {
        Log( LogLevel::ERROR_LEVEL, "Game path not found in registry\n" );
        Log( LogLevel::INFO, "Registry key: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AntiCheatExpert\n" );
        Log( LogLevel::INFO, "Value: DisplayIcon\n" );
        Log( LogLevel::INFO, "Press any key to exit...\n" );
        WaitForInputOrTimeout( AUTO_CLOSE_TIMEOUT_MS );
        return -1;
    }

    Log( LogLevel::INFO, "Game path found: %s\n", exePath.c_str( ) );

    if ( GetFileAttributesA( exePath.c_str( ) ) == INVALID_FILE_ATTRIBUTES ) {
        Log( LogLevel::ERROR_LEVEL, "Game executable not found at: %s\n", exePath.c_str( ) );
        Log( LogLevel::INFO, "Press any key to exit...\n" );
        WaitForInputOrTimeout( AUTO_CLOSE_TIMEOUT_MS );
        return -1;
    }

    InjectionThread( exePath );

    Log( LogLevel::INFO, "Press any key to exit (auto-close in 15 seconds)...\n" );
    WaitForInputOrTimeout( AUTO_CLOSE_TIMEOUT_MS );
    return 0;
}
