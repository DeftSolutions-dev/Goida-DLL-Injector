#pragma once

#include <string>
#include <vector>

struct GitHubRelease {
    std::string tag;
    std::string name;
    std::string body;
    std::string downloadUrl;
};

bool GetLatestRelease( GitHubRelease & release );
bool DownloadFile( const std::string & url, const std::string & filePath );
bool DownloadAndInstallWinRAR( );