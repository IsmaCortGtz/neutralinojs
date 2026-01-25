#include <string>
#include <optional>
#include <variant>
#include <iostream>

#include "lib/json/json.hpp"
#include "lib/clip/clip.h"
#include "lib/base64/base64.hpp"
#include "lib/pocket-http/pockethttp.hpp"
#include "helpers.h"
#include "errors.h"
#include "api/net/net.h"
#include "api/events/events.h"
#include <asio/thread_pool.hpp>
#include <asio/post.hpp>
#include <thread>

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

asio::thread_pool _pool(std::thread::hardware_concurrency());

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

json fetch(const json &input) {
    json output;

    optional<string> missingField = helpers::missingRequiredField(input, {"url", "method", "headers"});
    if (missingField) {
        output["error"] = errors::makeMissingArgErrorPayload(*missingField);
        return output;
    }

    asio::post(net::_pool, [input](){
        pockethttp::Http http;
        pockethttp::Response res;
        string resBody = "";
        string event = "net.fetch:" + input["uuidv4"].get<string>();
        
        res.body_callback = [&](const unsigned char* buffer, const size_t& size) {
            resBody.append((const char*)buffer, size);
        };

        int requestStatus = false;
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

                formDataReq.form_data.push_back(formDataItem);
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

        json result;
        if (!requestStatus) {
            result["success"] = false;
            result["error"] = errors::makeErrorPayload(errors::NE_NW_REQFAIL, input["url"].get<string>());
            events::dispatch(event, result);
            return;
        }

        
        result["success"] = true;
        result["returnValue"] = json::object();
        result["returnValue"]["status"] = res.status;
        result["returnValue"]["statusText"] = res.statusText;
        result["returnValue"]["headers"] = json::object();
        for (const auto& header : res.headers.keys()) {
            result["returnValue"]["headers"][header] = res.headers.get(header);
        }

        if (resBody.length() > 0) {
            result["returnValue"]["body"] = base64::to_base64(resBody);
        } else {
            result["returnValue"]["body"] = "";
        }

        events::dispatch(event, result);
    });

    output["success"] = true;
    output["message"] = "Request is being processed asynchronously.";
    return output;
}

} // namespace controllers
} // namespace net