#include "utils/github.hxx"
#include "core/injector.hxx"
#include <windows.h>
#include <winhttp.h>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")

static std::string ExtractJsonString( const std::string & json, const std::string & key ) {
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find( searchKey );
    if ( pos == std::string::npos ) return "";
    pos = json.find( ":", pos );
    if ( pos == std::string::npos ) return "";
    while ( pos < json.length( ) && ( json[ pos ] == ' ' || json[ pos ] == ':' ) ) pos++;
    if ( pos >= json.length( ) || json[ pos ] != '\"' ) return "";
    pos++;
    size_t startPos = pos;
    size_t endPos = pos;
    while ( endPos < json.length( ) ) {
        if ( json[ endPos ] == '\\' && endPos + 1 < json.length( ) ) {
            endPos += 2;
            continue;
        }
        if ( json[ endPos ] == '\"' ) break;
        endPos++;
    }
    if ( endPos >= json.length( ) ) return "";
    std::string result = json.substr( startPos, endPos - startPos );
    size_t replacePos = 0;
    while ( ( replacePos = result.find( "\\n", replacePos ) ) != std::string::npos ) {
        result.replace( replacePos, 2, "\n" );
        replacePos++;
    }
    while ( ( replacePos = result.find( "\\r", replacePos ) ) != std::string::npos ) {
        result.replace( replacePos, 2, "" );
    }
    while ( ( replacePos = result.find( "\\t", replacePos ) ) != std::string::npos ) {
        result.replace( replacePos, 2, "  " );
    }
    return result;
}

static std::string ExtractJsonArray( const std::string & json, const std::string & key ) {
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find( searchKey );
    if ( pos == std::string::npos ) return "";
    pos = json.find( "[", pos );
    if ( pos == std::string::npos ) return "";
    size_t bracketCount = 0;
    size_t startPos = pos;
    do {
        if ( json[ pos ] == '[' ) bracketCount++;
        else if ( json[ pos ] == ']' ) bracketCount--;
        pos++;
    } while ( bracketCount > 0 && pos < json.length( ) );
    return json.substr( startPos, pos - startPos );
}

static std::string ExtractDownloadUrl( const std::string & assetsJson ) {
    size_t pos = 0;
    while ( ( pos = assetsJson.find( "\"browser_download_url\"", pos ) ) != std::string::npos ) {
        pos = assetsJson.find( ":", pos );
        if ( pos == std::string::npos ) break;
        pos = assetsJson.find_first_of( "\"", pos );
        if ( pos == std::string::npos ) break;
        pos++;
        size_t endPos = assetsJson.find( "\"", pos );
        if ( endPos == std::string::npos ) break;
        std::string url = assetsJson.substr( pos, endPos - pos );
        if ( url.find( "Release.rar" ) != std::string::npos ) {
            return url;
        }
        pos = endPos;
    }
    return "";
}

bool GetLatestRelease( GitHubRelease & release ) {
    HINTERNET hSession = WinHttpOpen( L"Goida Launcher/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );
    if ( !hSession ) {
        Log( LogLevel::ERROR_LEVEL, "Failed to initialize WinHTTP\n" );
        return false;
    }

    HINTERNET hConnect = WinHttpConnect( hSession, L"api.github.com", INTERNET_DEFAULT_HTTPS_PORT, 0 );
    if ( !hConnect ) {
        Log( LogLevel::ERROR_LEVEL, "Failed to connect to GitHub API\n" );
        WinHttpCloseHandle( hSession );
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest( hConnect, L"GET", L"/repos/0xCiel/Alya-Endfield/releases/latest", nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE );
    if ( !hRequest ) {
        Log( LogLevel::ERROR_LEVEL, "Failed to create HTTP request\n" );
        WinHttpCloseHandle( hConnect );
        WinHttpCloseHandle( hSession );
        return false;
    }

    if ( !WinHttpSendRequest( hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0 ) ) {
        Log( LogLevel::ERROR_LEVEL, "Failed to send HTTP request\n" );
        WinHttpCloseHandle( hRequest );
        WinHttpCloseHandle( hConnect );
        WinHttpCloseHandle( hSession );
        return false;
    }

    if ( !WinHttpReceiveResponse( hRequest, nullptr ) ) {
        Log( LogLevel::ERROR_LEVEL, "Failed to receive HTTP response\n" );
        WinHttpCloseHandle( hRequest );
        WinHttpCloseHandle( hConnect );
        WinHttpCloseHandle( hSession );
        return false;
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof( statusCode );
    WinHttpQueryHeaders( hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &statusCode, &statusCodeSize, nullptr );
    if ( statusCode != 200 ) {
        Log( LogLevel::ERROR_LEVEL, "GitHub API returned status code: %lu\n", statusCode );
        WinHttpCloseHandle( hRequest );
        WinHttpCloseHandle( hConnect );
        WinHttpCloseHandle( hSession );
        return false;
    }

    std::string response;
    DWORD bytesAvailable = 0;
    do {
        if ( !WinHttpQueryDataAvailable( hRequest, &bytesAvailable ) ) break;
        if ( bytesAvailable == 0 ) break;
        std::vector< char > buffer( bytesAvailable );
        DWORD bytesRead = 0;
        if ( !WinHttpReadData( hRequest, buffer.data( ), bytesAvailable, &bytesRead ) ) break;
        response.append( buffer.data( ), bytesRead );
    } while ( bytesAvailable > 0 );

    WinHttpCloseHandle( hRequest );
    WinHttpCloseHandle( hConnect );
    WinHttpCloseHandle( hSession );

    if ( response.empty( ) ) {
        Log( LogLevel::ERROR_LEVEL, "Empty response from GitHub API\n" );
        return false;
    }

    release.tag = ExtractJsonString( response, "tag_name" );
    release.name = ExtractJsonString( response, "name" );
    release.body = ExtractJsonString( response, "body" );
    std::string assetsJson = ExtractJsonArray( response, "assets" );
    release.downloadUrl = ExtractDownloadUrl( assetsJson );

    if ( release.tag.empty( ) || release.downloadUrl.empty( ) ) {
        Log( LogLevel::ERROR_LEVEL, "Failed to parse release information\n" );
        return false;
    }

    return true;
}

bool DownloadFile( const std::string & url, const std::string & filePath ) {
    extern void DebugLog( const char * format, ... );
    DebugLog( "DownloadFile: Starting download from %s to %s\n", url.c_str( ), filePath.c_str( ) );

    HINTERNET hSession = WinHttpOpen( L"Goida Launcher/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );
    if ( !hSession ) {
        DWORD error = GetLastError( );
        Log( LogLevel::ERROR_LEVEL, "Failed to initialize WinHTTP (error: %lu)\n", error );
        DebugLog( "DownloadFile: WinHttpOpen failed, error: %lu\n", error );
        return false;
    }
    DebugLog( "DownloadFile: WinHTTP session opened\n" );

    size_t protocolEnd = url.find( "://" );
    if ( protocolEnd == std::string::npos ) {
        Log( LogLevel::ERROR_LEVEL, "Invalid URL format: %s\n", url.c_str( ) );
        DebugLog( "DownloadFile: Invalid URL format\n" );
        WinHttpCloseHandle( hSession );
        return false;
    }

    bool isHttps = url.substr( 0, protocolEnd ) == "https";
    size_t hostStart = protocolEnd + 3;
    size_t pathStart = url.find( "/", hostStart );
    if ( pathStart == std::string::npos ) {
        pathStart = url.length( );
    }

    std::string host = url.substr( hostStart, pathStart - hostStart );
    std::string path = pathStart < url.length( ) ? url.substr( pathStart ) : "/";
    std::wstring wHost( host.begin( ), host.end( ) );
    std::wstring wPath( path.begin( ), path.end( ) );

    DebugLog( "DownloadFile: Host: %s, Path: %s, HTTPS: %s\n", host.c_str( ), path.c_str( ), isHttps ? "yes" : "no" );

    INTERNET_PORT port = isHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    HINTERNET hConnect = WinHttpConnect( hSession, wHost.c_str( ), port, 0 );
    if ( !hConnect ) {
        DWORD error = GetLastError( );
        Log( LogLevel::ERROR_LEVEL, "Failed to connect to host %s (error: %lu)\n", host.c_str( ), error );
        DebugLog( "DownloadFile: WinHttpConnect failed, error: %lu\n", error );
        WinHttpCloseHandle( hSession );
        return false;
    }
    DebugLog( "DownloadFile: Connected to host\n" );

    DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest( hConnect, L"GET", wPath.c_str( ), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags );
    if ( !hRequest ) {
        DWORD error = GetLastError( );
        Log( LogLevel::ERROR_LEVEL, "Failed to create HTTP request (error: %lu)\n", error );
        DebugLog( "DownloadFile: WinHttpOpenRequest failed, error: %lu\n", error );
        WinHttpCloseHandle( hConnect );
        WinHttpCloseHandle( hSession );
        return false;
    }
    DebugLog( "DownloadFile: HTTP request created\n" );

    if ( !WinHttpSendRequest( hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0 ) ) {
        DWORD error = GetLastError( );
        Log( LogLevel::ERROR_LEVEL, "Failed to send HTTP request (error: %lu)\n", error );
        DebugLog( "DownloadFile: WinHttpSendRequest failed, error: %lu\n", error );
        WinHttpCloseHandle( hRequest );
        WinHttpCloseHandle( hConnect );
        WinHttpCloseHandle( hSession );
        return false;
    }
    DebugLog( "DownloadFile: HTTP request sent\n" );

    if ( !WinHttpReceiveResponse( hRequest, nullptr ) ) {
        DWORD error = GetLastError( );
        Log( LogLevel::ERROR_LEVEL, "Failed to receive HTTP response (error: %lu)\n", error );
        DebugLog( "DownloadFile: WinHttpReceiveResponse failed, error: %lu\n", error );
        WinHttpCloseHandle( hRequest );
        WinHttpCloseHandle( hConnect );
        WinHttpCloseHandle( hSession );
        return false;
    }
    DebugLog( "DownloadFile: HTTP response received\n" );

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof( statusCode );
    WinHttpQueryHeaders( hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &statusCode, &statusCodeSize, nullptr );
    DebugLog( "DownloadFile: HTTP status code: %lu\n", statusCode );
    if ( statusCode != 200 ) {
        Log( LogLevel::ERROR_LEVEL, "Download failed with status code: %lu\n", statusCode );
        WinHttpCloseHandle( hRequest );
        WinHttpCloseHandle( hConnect );
        WinHttpCloseHandle( hSession );
        return false;
    }

    size_t lastSlash = filePath.find_last_of( "\\/" );
    if ( lastSlash != std::string::npos ) {
        std::string dirPath = filePath.substr( 0, lastSlash );
        CreateDirectoryA( dirPath.c_str( ), nullptr );
        DebugLog( "DownloadFile: Created directory if needed: %s\n", dirPath.c_str( ) );
    }

    HANDLE hFile = CreateFileA( filePath.c_str( ), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );
    if ( hFile == INVALID_HANDLE_VALUE ) {
        DWORD error = GetLastError( );
        Log( LogLevel::ERROR_LEVEL, "Failed to create file: %s (error: %lu)\n", filePath.c_str( ), error );
        DebugLog( "DownloadFile: CreateFileA failed, error: %lu\n", error );
        WinHttpCloseHandle( hRequest );
        WinHttpCloseHandle( hConnect );
        WinHttpCloseHandle( hSession );
        return false;
    }
    DebugLog( "DownloadFile: File opened for writing\n" );

    DWORD bytesAvailable = 0;
    DWORD totalBytes = 0;
    do {
        if ( !WinHttpQueryDataAvailable( hRequest, &bytesAvailable ) ) {
            DWORD error = GetLastError( );
            DebugLog( "DownloadFile: WinHttpQueryDataAvailable failed, error: %lu\n", error );
            break;
        }
        if ( bytesAvailable == 0 ) break;
        std::vector< char > buffer( bytesAvailable );
        DWORD bytesRead = 0;
        if ( !WinHttpReadData( hRequest, buffer.data( ), bytesAvailable, &bytesRead ) ) {
            DWORD error = GetLastError( );
            DebugLog( "DownloadFile: WinHttpReadData failed, error: %lu\n", error );
            break;
        }
        DWORD bytesWritten = 0;
        if ( !WriteFile( hFile, buffer.data( ), bytesRead, &bytesWritten, nullptr ) ) {
            DWORD error = GetLastError( );
            DebugLog( "DownloadFile: WriteFile failed, error: %lu\n", error );
            break;
        }
        totalBytes += bytesWritten;
        DebugLog( "DownloadFile: Written %lu bytes (total: %lu)\n", bytesWritten, totalBytes );
    } while ( bytesAvailable > 0 );

    CloseHandle( hFile );
    WinHttpCloseHandle( hRequest );
    WinHttpCloseHandle( hConnect );
    WinHttpCloseHandle( hSession );

    if ( totalBytes == 0 ) {
        Log( LogLevel::ERROR_LEVEL, "Download completed but no data was written\n" );
        DebugLog( "DownloadFile: No data written\n" );
        return false;
    }

    Log( LogLevel::SUCCESS, "Downloaded %lu bytes to %s\n", totalBytes, filePath.c_str( ) );
    DebugLog( "DownloadFile: Download completed successfully, %lu bytes\n", totalBytes );
    return true;
}
