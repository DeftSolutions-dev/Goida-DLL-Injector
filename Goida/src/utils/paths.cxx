#include "utils/paths.hxx"
#include "core/injector.hxx"
#include <shlwapi.h>
#include <winreg.h>
#include <string>
#include <fstream>

#pragma comment(lib, "shlwapi.lib")

std::string GetExecutableDirectory( ) {
    char path[ MAX_PATH ];
    GetModuleFileNameA( nullptr, path, MAX_PATH );
    PathRemoveFileSpecA( path );
    return std::string( path );
}

std::string GetMainDirectory( ) {
    return GetExecutableDirectory( ) + "\\Main";
}

std::string GetDllPath( ) {
    return GetMainDirectory( ) + "\\Cheat.dll";
}

std::string GetGameExePath( ) {
    HKEY hKey;
    char buffer[ MAX_PATH ] = { 0 };
    DWORD bufferSize = sizeof( buffer );

    LONG result = RegOpenKeyExA( HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AntiCheatExpert",
        0, KEY_READ, &hKey );

    if ( result != ERROR_SUCCESS ) {
        Log( LogLevel::DEBUG, "Registry key not found (error: %lu)\n", result );
        return "";
    }

    result = RegQueryValueExA( hKey, "DisplayIcon", nullptr, nullptr,
        reinterpret_cast< LPBYTE >( buffer ), &bufferSize );
    RegCloseKey( hKey );

    if ( result != ERROR_SUCCESS ) {
        Log( LogLevel::DEBUG, "DisplayIcon value not found (error: %lu)\n", result );
        return "";
    }

    std::string registryPath = buffer;

    size_t endfieldPos = registryPath.find( "\\EndField Game\\" );
    if ( endfieldPos == std::string::npos ) {
        size_t acePos = registryPath.find( "AntiCheatExpert" );
        if ( acePos != std::string::npos ) {
            size_t slashPos = registryPath.find_last_of( "\\", acePos - 1 );
            if ( slashPos != std::string::npos ) {
                std::string basePath = registryPath.substr( 0, slashPos + 1 );
                std::string gamePath = basePath + "EndField Game\\Endfield.exe";
                return gamePath;
            }
        }
        return "";
    }

    std::string gamePath = registryPath.substr( 0, endfieldPos + strlen( "\\EndField Game\\" ) ) + "Endfield.exe";
    return gamePath;
}

std::string GetTempDirectory( ) {
    char tempPath[ MAX_PATH ];
    if ( GetTempPathA( MAX_PATH, tempPath ) == 0 ) {
        return GetExecutableDirectory( );
    }
    return std::string( tempPath );
}

std::string GetVersionFilePath( ) {
    return GetExecutableDirectory( ) + "\\version.txt";
}

std::string GetSavedVersion( ) {
    std::string versionFile = GetVersionFilePath( );
    std::ifstream file( versionFile );
    if ( !file.is_open( ) ) {
        return "";
    }
    std::string version;
    std::getline( file, version );
    file.close( );
    return version;
}

void SaveVersion( const std::string & version ) {
    std::string versionFile = GetVersionFilePath( );
    std::ofstream file( versionFile );
    if ( file.is_open( ) ) {
        file << version;
        file.close( );
    }
}
