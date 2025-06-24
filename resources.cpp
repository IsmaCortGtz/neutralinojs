#include <string>
#include <iostream>
#include <fstream>
#include <regex>
#include <vector>
#include <filesystem>
#include <limits.h>

#include "lib/easylogging/easylogging++.h"
#include "lib/json/json.hpp"
#include "helpers.h"
#include "errors.h"
#include "settings.h"
#include "resources.h"
#include "api/debug/debug.h"
#include "api/fs/fs.h"

#define NEU_APP_RES_FILE "/resources.neu"
#define NEU_APP_EMBEDDED_BOUNDARY "NEUEMBEDBOUNDARY"

using namespace std;
using json = nlohmann::json;

namespace resources {

json fileTree = nullptr;
uint64_t asarEmbeddedOffset = 0;
unsigned int asarHeaderSize;
resources::ResourceMode mode = resources::ResourceModeBundle;

ifstream __getSelfBinary() {
#ifdef __linux__
    const char* selfPath = "/proc/self/exe";
#elif _WIN32
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);
#elif __APPLE__
    char selfPath[PATH_MAX];
    uint32_t size = sizeof(selfPath);
    _NSGetExecutablePath(selfPath, &size);
#endif

    ifstream selfBinary(selfPath, ios::binary);
    return selfBinary;
}

pair<unsigned long, string> __seekFilePos(const string &path, json node) {
    vector<string> pathSegments = helpers::split(path, '/');
    json json = node;
    for(const auto &pathSegment: pathSegments) {
        if(pathSegment.size() == 0 || json.is_null() || json["files"].is_null())
            continue;
        json = json["files"][pathSegment];
    }
    if(!json.is_null())
        return make_pair(json["size"].get<unsigned long>(), json["offset"].get<string>());
    return make_pair(-1, "");
}

// Needs explicit close later
ifstream __openResourceFile() {
    ifstream asarArchive;
    string resFileName = NEU_APP_RES_FILE;
    resFileName = settings::joinAppPath(resFileName);
    asarArchive.open(CONVSTR(resFileName), ios::binary);
    if(asarArchive) {
        return asarArchive;
    }

    ifstream selfBinary = __getSelfBinary();
    if (!selfBinary) {
        if (!asarArchive) {
            debug::log(debug::LogTypeError, errors::makeErrorMsg(errors::NE_RS_TREEGER, resFileName));  
        }
        return asarArchive;
    }

    selfBinary.seekg(0, ios::end);
    size_t fileSize = selfBinary.tellg();
    if (fileSize < 16) {   
        if (!asarArchive) {
            debug::log(debug::LogTypeError, errors::makeErrorMsg(errors::NE_RS_TREEGER, resFileName));  
        }
        return asarArchive;
    }

    char marker[strlen(NEU_APP_EMBEDDED_BOUNDARY)];
    uint8_t offsetBytes[8];
    selfBinary.seekg(fileSize - 8 - strlen(NEU_APP_EMBEDDED_BOUNDARY));
    selfBinary.read(marker, strlen(NEU_APP_EMBEDDED_BOUNDARY));
    selfBinary.read(reinterpret_cast<char*>(offsetBytes), 8);

    if (strncmp(marker, NEU_APP_EMBEDDED_BOUNDARY, strlen(NEU_APP_EMBEDDED_BOUNDARY)) != 0) {
        if (!asarArchive) {
            debug::log(debug::LogTypeError, errors::makeErrorMsg(errors::NE_RS_TREEGER, resFileName));  
        }
        return asarArchive;
    }

    uint64_t neuOffset = 0;
    for (int i = 0; i < 8; ++i) {
        neuOffset |= static_cast<uint64_t>(offsetBytes[i]) << ((7 - i) * 8);
    }

    if (neuOffset >= fileSize) {   
        if (!asarArchive) {
            debug::log(debug::LogTypeError, errors::makeErrorMsg(errors::NE_RS_TREEGER, resFileName));  
        }
        return asarArchive;
    }
    
    asarEmbeddedOffset = neuOffset;
    selfBinary.seekg(neuOffset);
    return selfBinary;
}

fs::FileReaderResult __getFileFromBundle(const string &filename) {
    fs::FileReaderResult fileReaderResult;
    pair<long, string> p = __seekFilePos(filename, fileTree);
    if(p.first != -1) {
        ifstream asarArchive = __openResourceFile();
        if (!asarArchive) {
            fileReaderResult.status = errors::NE_RS_TREEGER;
            return fileReaderResult;
        }
        unsigned long size = p.first;
        unsigned long uOffset = stoi(p.second) + asarEmbeddedOffset;

        vector<char>fileBuf ( size );
        asarArchive.seekg(asarHeaderSize + uOffset);
        asarArchive.read(fileBuf.data(), size);
        string fileContent(fileBuf.begin(), fileBuf.end());
        fileReaderResult.data = fileContent;
        asarArchive.close();
   }
   else {
        fileReaderResult.status = errors::NE_RS_NOPATHE;
   }
   return fileReaderResult;
}

bool __makeFileTree() {
    ifstream asarArchive = __openResourceFile();
    if (!asarArchive) {
        return false;
    }

    char *sizeBuf = new char[8];
    asarArchive.read(sizeBuf, 8);
    unsigned int size = *(unsigned int *)(sizeBuf + 4) - 8;

    delete[] sizeBuf;

    asarHeaderSize = size + 16;
    vector<char> headerBuf(size);
    asarArchive.seekg(16 + asarEmbeddedOffset);
    asarArchive.read(headerBuf.data(), size);
    json files;
    string headerContent(headerBuf.begin(), headerBuf.end());
    asarArchive.close();
    try {
        files = json::parse(headerContent);
    }
    catch(exception e) {
        debug::log(debug::LogTypeError, e.what());
    }
    fileTree = files;
    return fileTree != nullptr;
}

bool extractFile(const string &filename, const string &outputFilename) {
    fs::FileReaderResult fileReaderResult = resources::getFile(filename);
    if(fileReaderResult.status != errors::NE_ST_OK) {
        return false;
    }
    auto extractPath = filesystem::path(CONVSTR(outputFilename));
    if(!extractPath.parent_path().empty()) {
        filesystem::create_directories(extractPath.parent_path());
    }
   
    fs::FileWriterOptions fileWriterOptions;
    fileWriterOptions.filename = outputFilename;
    fileWriterOptions.data = fileReaderResult.data;
    return fs::writeFile(fileWriterOptions);
}

fs::FileReaderResult getFile(const string &filename) {
    if(resources::isBundleMode()) {
        return __getFileFromBundle(filename);
    }
    return fs::readFile(settings::joinAppPath(filename));
}

void init() {
    if(resources::isDirMode()) {
        return;
    }
    bool resourceLoaderStatus = __makeFileTree();
    if(!resourceLoaderStatus) {
        resources::setMode(resources::ResourceModeDir); // fallback to directory mode
    }
}

void setMode(const resources::ResourceMode m) {
    mode = m;
}

resources::ResourceMode getMode() {
    return mode;
}

bool isDirMode() {
   return resources::getMode() == resources::ResourceModeDir;
}

bool isBundleMode() {
   return resources::getMode() == resources::ResourceModeBundle;
}

json getFileTree() {
   return fileTree;
}

string getModeString() {
    return resources::isDirMode() ? "directory" : "bundle";
}

} // namespace resources
