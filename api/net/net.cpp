#include <string>
#include <optional>
#include <variant>

#include "lib/json/json.hpp"
#include "lib/clip/clip.h"
#include "lib/base64/base64.hpp"
#include "lib/pockethttp/pockethttp.hpp"
#include "helpers.h"
#include "errors.h"
#include "api/net/net.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <ifaddrs.h>
    #include <net/if.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

using namespace std;
using json = nlohmann::json;

namespace net {
namespace controllers {

json resolveHost(const json &input) {
    json output;

    if (!helpers::hasField(input, "hostname")) {
        output["error"] = errors::makeMissingArgErrorPayload("hostname");
        return output;
    }

#ifdef _WIN32
    auto& manager = pockethttp::WinSockManager::getInstance();
    if (!manager.isInitialized()) {
      output["error"] = errors::makeErrorPayload(errors::NE_NW_WIN32ER, "WinSock initialization failed.");
      return output;
    }
#endif

    string hostname = input["hostname"].get<string>();
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0) {
        output["error"] = errors::makeErrorPayload(errors::NE_NW_DNSRESV, input["hostname"].get<string>());
        return output;
    }

    
    output["returnValue"] = json::array();
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        json addr;
        addr["address"] = "";
        addr["family"] = (p->ai_family == AF_INET) ? "ipv4" : (p->ai_family == AF_INET6) ? "ipv6" : "unknown";
        char ipstr[INET6_ADDRSTRLEN];
        void* addrPtr;

        if      (p->ai_family == AF_INET ) addrPtr = &((struct sockaddr_in* )p->ai_addr)->sin_addr;
        else if (p->ai_family == AF_INET6) addrPtr = &((struct sockaddr_in6*)p->ai_addr)->sin6_addr;
        else continue;

        inet_ntop(p->ai_family, addrPtr, ipstr, sizeof(ipstr));
        addr["address"] = string(ipstr);
        output["returnValue"].push_back(addr);
    }

    freeaddrinfo(res);
    output["success"] = true;
    return output;
}

json isOnline(const json &input) {
    json output;
    output["success"] = true;

#ifdef _WIN32
    IP_ADAPTER_ADDRESSES* adapters = nullptr;
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &size) == ERROR_BUFFER_OVERFLOW) {
        adapters = (IP_ADAPTER_ADDRESSES*)malloc(size);
    }

    if (adapters == nullptr) {
        output["returnValue"] = false;
        return output;
    }

    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &size) != NO_ERROR) {
        free(adapters);
        output["returnValue"] = false;
        return output;
    }

    for (IP_ADAPTER_ADDRESSES* a = adapters; a != nullptr; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (a->FirstGatewayAddress == nullptr) continue;
        if (a->FirstUnicastAddress == nullptr) continue;
        
        free(adapters);
        output["returnValue"] = true;
        return output;
    }

    free(adapters);
    output["returnValue"] = false;
    return output;
#else
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        output["returnValue"] = false;
        return output;
    }

    bool found = false;
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if ((ifa->ifa_flags & IFF_UP) == 0) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (ifa->ifa_addr->sa_family != AF_INET && ifa->ifa_addr->sa_family != AF_INET6) continue;
        found = true;
        break;
    }

    freeifaddrs(ifaddr);
    output["returnValue"] = found;
    return output;
#endif
}

json fetch(const json &input) {
    json output;

    optional<string> missingField = helpers::missingRequiredField(input, {"url", "method", "headers"});
    if (missingField) {
        output["error"] = errors::makeMissingArgErrorPayload(*missingField);
        return output;
    }

    pockethttp::Http http;
    pockethttp::Response res;
    string resBody = "";
    
    res.body_callback = [&](const unsigned char* buffer, const size_t& size) {
        resBody.append((const char*)buffer, size);
    };

    bool requestStatus = false;
    bool hasBody = input.contains("body") && !input["body"].is_null();
    bool isFormData = input.value("isFormData", false);

    if (hasBody && isFormData) {
        pockethttp::FormDataRequest formDataReq;
        formDataReq.url = input["url"].get<string>();
        formDataReq.method = input["method"].get<string>();
        formDataReq.headers = pockethttp::Headers::parse(input.value("headers", json::object()));

        for (const auto& item : input["body"]) {
            pockethttp::FormDataItem formDataItem;
            formDataItem.name = item["name"].get<string>();

            if (item.contains("filename") && !item["filename"].is_null()) {
                formDataItem.value = base64::from_base64(item["value"].get<string>());
                formDataItem.filename = item["filename"].get<string>();
                formDataItem.content_type = item.value("contentType", "application/octet-stream");
                formDataItem.content_length = item.value("contentLength", formDataItem.value.size());
            } else {
                formDataItem.value = item["value"].get<string>();
            }
        }

        requestStatus = http.request(formDataReq, res);

    } else {
        pockethttp::Request request;
        request.url = input["url"].get<string>();
        request.method = input["method"].get<string>();
        request.headers = pockethttp::Headers::parse(input.value("headers", json::object()));

        if (hasBody) {
            request.body = base64::from_base64(input["body"].get<string>());
        }

        requestStatus = http.request(request, res);
    }

    if (!requestStatus) {
        output["error"] = errors::makeErrorPayload(errors::NE_NW_REQFAIL, input["url"].get<string>());
        return output;
    }

    output["success"] = true;
    output["returnValue"] = json::object();
    output["returnValue"]["status"] = res.status;
    output["returnValue"]["statusText"] = res.statusText;
    output["returnValue"]["headers"] = json::object();
    for (const auto& header : res.headers.keys()) {
        output["returnValue"]["headers"][header] = res.headers.get(header);
    }

    if (resBody.length() > 0) {
        output["returnValue"]["body"] = base64::to_base64(resBody);
    } else {
        output["returnValue"]["body"] = "";
    }

    return output;
}

} // namespace controllers
} // namespace net
