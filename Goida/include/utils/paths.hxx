#pragma once

#include <string>

std::string GetExecutableDirectory( );
std::string GetMainDirectory( );
std::string GetDllPath( );
std::string GetGameExePath( );
std::string GetTempDirectory( );
std::string GetVersionFilePath( );
std::string GetSavedVersion( );
void SaveVersion( const std::string & version );