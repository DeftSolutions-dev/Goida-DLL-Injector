#include "utils/archive.hxx"
#include "core/injector.hxx"
#include "utils/paths.hxx"
#include "utils/unrarbyte.hxx"
#include <shlwapi.h>
#include <string>
#include <fstream>
#include <cstring>

extern void DebugLog( const char * format, ... );

#pragma comment(lib, "shlwapi.lib")

static bool ExtractUnrarFromBytes( const std::string & outputPath ) {
    DebugLog( "ExtractUnrarFromBytes: Output path: %s\n", outputPath.c_str( ) );

    size_t lastSlash = outputPath.find_last_of( "\\/" );
    if ( lastSlash != std::string::npos ) {
        std::string dirPath = outputPath.substr( 0, lastSlash );
        CreateDirectoryA( dirPath.c_str( ), nullptr );
        DebugLog( "ExtractUnrarFromBytes: Created directory if needed: %s\n", dirPath.c_str( ) );
    }

    HANDLE hFile = CreateFileA( outputPath.c_str( ), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );
    if ( hFile == INVALID_HANDLE_VALUE ) {
        DWORD error = GetLastError( );
        Log( LogLevel::ERROR_LEVEL, "Failed to create unrar.exe file: %s (error: %lu)\n", outputPath.c_str( ), error );
        DebugLog( "ExtractUnrarFromBytes: CreateFileA failed, error: %lu\n", error );
        return false;
    }

    DWORD bytesWritten = 0;
    if ( !WriteFile( hFile, unrarbyte, static_cast< DWORD >( unrarbyte_size ), &bytesWritten, nullptr ) ) {
        DWORD error = GetLastError( );
        Log( LogLevel::ERROR_LEVEL, "Failed to write unrar.exe file (error: %lu)\n", error );
        DebugLog( "ExtractUnrarFromBytes: WriteFile failed, error: %lu\n", error );
        CloseHandle( hFile );
        DeleteFileA( outputPath.c_str( ) );
        return false;
    }

    CloseHandle( hFile );

    if ( bytesWritten != unrarbyte_size ) {
        Log( LogLevel::ERROR_LEVEL, "Failed to write all bytes to unrar.exe\n" );
        DebugLog( "ExtractUnrarFromBytes: Written %lu bytes, expected %zu bytes\n", bytesWritten, unrarbyte_size );
        DeleteFileA( outputPath.c_str( ) );
        return false;
    }

    Log( LogLevel::SUCCESS, "Extracted unrar.exe from embedded bytes\n" );
    DebugLog( "ExtractUnrarFromBytes: Successfully extracted %zu bytes to %s\n", unrarbyte_size, outputPath.c_str( ) );
    return true;
}

static bool ExtractWithUnrar( const std::string & rarPath, const std::string & outputPath ) {
    std::string tempDir = GetTempDirectory( );
    if ( tempDir.empty( ) || ( tempDir.back( ) != '\\' && tempDir.back( ) != '/' ) ) {
        tempDir += "\\";
    }
    std::string unrarPath = tempDir + "unrar.exe";

    DebugLog( "ExtractWithUnrar: Temp directory: %s\n", tempDir.c_str( ) );
    DebugLog( "ExtractWithUnrar: Unrar path: %s\n", unrarPath.c_str( ) );

    if ( GetFileAttributesA( unrarPath.c_str( ) ) == INVALID_FILE_ATTRIBUTES ) {
        DebugLog( "ExtractWithUnrar: unrar.exe not found, extracting from embedded bytes...\n" );
        if ( !ExtractUnrarFromBytes( unrarPath ) ) {
            DebugLog( "ExtractWithUnrar: Failed to extract unrar.exe from bytes\n" );
            return false;
        }
    } else {
        DebugLog( "ExtractWithUnrar: unrar.exe already exists\n" );
    }

    DebugLog( "ExtractWithUnrar: Using unrar.exe at %s\n", unrarPath.c_str( ) );
    std::string mainDir = GetMainDirectory( );
    CreateDirectoryA( mainDir.c_str( ), nullptr );
    std::string cmdLine = "\"" + unrarPath + "\" x -o+ \"" + rarPath + "\" Cheat.dll \"" + mainDir + "\"";

    DebugLog( "ExtractWithUnrar: Command: %s\n", cmdLine.c_str( ) );

    STARTUPINFOA si = { sizeof( STARTUPINFOA ) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char * cmdLineBuf = new char[ cmdLine.length( ) + 1 ];
    strcpy_s( cmdLineBuf, cmdLine.length( ) + 1, cmdLine.c_str( ) );

    if ( !CreateProcessA( nullptr, cmdLineBuf, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi ) ) {
        DWORD error = GetLastError( );
        DebugLog( "ExtractWithUnrar: CreateProcess failed, error: %lu\n", error );
        delete[ ] cmdLineBuf;
        DeleteFileA( unrarPath.c_str( ) );
        return false;
    }

    delete[ ] cmdLineBuf;

    WaitForSingleObject( pi.hProcess, INFINITE );
    DWORD exitCode = 0;
    GetExitCodeProcess( pi.hProcess, &exitCode );
    CloseHandle( pi.hProcess );
    CloseHandle( pi.hThread );

    DebugLog( "ExtractWithUnrar: Exit code: %lu\n", exitCode );

    DeleteFileA( unrarPath.c_str( ) );
    DebugLog( "ExtractWithUnrar: Cleaned up unrar.exe\n" );

    if ( exitCode != 0 ) {
        DebugLog( "ExtractWithUnrar: unrar.exe exited with error code\n" );
        return false;
    }

    bool exists = GetFileAttributesA( outputPath.c_str( ) ) != INVALID_FILE_ATTRIBUTES;
    DebugLog( "ExtractWithUnrar: Cheat.dll exists: %s\n", exists ? "yes" : "no" );

    return exists;
}

bool ExtractCheatDllFromRar( const std::string & rarPath, const std::string & outputPath ) {
    Log( LogLevel::INFO, "Extracting Cheat.dll from archive...\n" );

    if ( ExtractWithUnrar( rarPath, outputPath ) ) {
        Log( LogLevel::SUCCESS, "Successfully extracted Cheat.dll\n" );
        DeleteFileA( rarPath.c_str( ) );
        return true;
    }

    Log( LogLevel::ERROR_LEVEL, "Failed to extract Cheat.dll from archive\n" );
    return false;
}
