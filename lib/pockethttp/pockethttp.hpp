/*
 * Copyright (c) 2025 Ismael Cortés Gutiérrez
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// Auto-generated merged header

// pockethttp/Buffer.hpp
#ifndef POCKET_HTTP_BUFFER_HPP
#define POCKET_HTTP_BUFFER_HPP

#include <cstddef>

namespace pockethttp {

  namespace Buffer {

    const size_t error = static_cast<size_t>(-1);

    size_t find(const unsigned char* buffer, const size_t& size, const unsigned char* to_find, const size_t& to_find_size);
    
    bool equal(const unsigned char* buffer, const unsigned char* to_find, const size_t& size);

  }

} // namespace pockethttp

#endif // POCKET_HTTP_BUFFER_HPP

// pockethttp/Timestamp.hpp
#ifndef POCKET_HTTP_TIMESTAMP_HPP
#define POCKET_HTTP_TIMESTAMP_HPP

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace pockethttp {

  namespace Timestamp {

    int64_t getCurrentTimestamp();
    std::string getFormatedTimestamp();

  } // namespace Timestamp

} // namespace pockethttp

#endif // POCKET_HTTP_TIMESTAMP_HPP

// pockethttp/Random.hpp
#ifndef POCKET_HTTP_RANDOM_HPP
#define POCKET_HTTP_RANDOM_HPP

#include <random>
#include <string>

namespace pockethttp {

  namespace random {

    inline std::string generateRandomString(size_t length = 22) {
      const std::string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
      std::random_device rd;
      std::mt19937 generator(rd());
      std::uniform_int_distribution<> distribution(0, characters.size() - 1);

      std::string random_string;
      for (size_t i = 0; i < length; ++i) {
        random_string += characters[distribution(generator)];
      }

      return random_string;
    }

  } // namespace random
  
} // namespace pockethttp

#endif // POCKET_HTTP_RANDOM_HPP

// pockethttp/Logs.hpp
#ifndef POCKET_HTTP_LOGS_HPP
#define POCKET_HTTP_LOGS_HPP

// #include "pockethttp/Timestamp.hpp"

#if defined(USE_POCKET_HTTP_LOG) || defined(USE_POCKET_HTTP_ERR)
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#endif


#ifdef USE_POCKET_HTTP_LOG
#define pockethttp_log(...)   (std::cout << "[" << pockethttp::Timestamp::getFormatedTimestamp() << "] [POCKETHTTP] [LOG] " << __VA_ARGS__ << std::endl)
#else // USE_POCKET_HTTP_LOG
#define pockethttp_log(...)   ((void)0)
#endif // USE_POCKET_HTTP_LOG


#ifdef USE_POCKET_HTTP_ERR
#define pockethttp_error(...) (std::cerr << "[" << pockethttp::Timestamp::getFormatedTimestamp() << "] [POCKETHTTP] [ERR] " << __VA_ARGS__ << std::endl)
#else // USE_POCKET_HTTP_ERR
#define pockethttp_error(...) ((void)0)
#endif // USE_POCKET_HTTP_ERR


#endif // POCKET_HTTP_LOGS_HPP

// pockethttp/Decompress.hpp
#ifndef POCKET_HTTP_DECOMPRESS_HPP
#define POCKET_HTTP_DECOMPRESS_HPP

#include <miniz/miniz.h>
#include <cstddef>
#include <cstdint>
#include <functional>

#define POCKET_HTTP_DECOMPRESS_OUTPUT_CHUNK_SIZE 16384 // 16 kb

namespace pockethttp {

  enum DecompressionAlgorithm {
    NONE,
    GZIP,
    DEFLATE
  };

  enum DecompressionState {
    INITIALIZED,
    DECOMPRESSING,
    FINISHED,
    DECOMPRESS_ERROR
  };

  class Decompressor {
    private:
      mz_stream stream;
      DecompressionAlgorithm algorithm;

      bool header_processed = false;
      size_t get_gzip_header_length(const uint8_t* data, size_t size);
      DecompressionState state;
      
    public:
      Decompressor(DecompressionAlgorithm algorithm);
      ~Decompressor();

      DecompressionState init();
      DecompressionState decompress(
        const unsigned char* input, 
        size_t input_size, 
        std::function<void(const unsigned char* buffer, const size_t& size)> output_callback
      );
      
      const uint8_t* getPendingInputPtr() const;
      size_t getPendingInputSize() const;
  };

} // namespace pockethttp

#endif // POCKET_HTTP_DECOMPRESS_HPP

// pockethttp/Headers.hpp
#ifndef POCKET_HTTP_HEADERS_HPP
#define POCKET_HTTP_HEADERS_HPP

#include <map>
#include <string>
#include <vector>

namespace pockethttp {

  class Headers {
    public:
      static Headers parse(const std::string& rawHeaders);
      
      void load(const std::string& rawHeaders);
      std::string dump() const;
      std::vector<std::string> keys() const;
      std::string get(const std::string& key) const;
      void set(const std::string& key, const std::string& value);
      bool has(const std::string& key) const;
      void remove(const std::string& key);

    private:
      std::map<std::string, std::string> headers_;
  };

} // namespace pockethttp

#endif // POCKET_HTTP_HEADERS_HPP

// pockethttp/Request.hpp
#ifndef POCKET_HTTP_REQUEST_HPP
#define POCKET_HTTP_REQUEST_HPP

// #include "pockethttp/Buffer.hpp"
// #include "pockethttp/Headers.hpp"
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>
#include <functional>


namespace pockethttp {
  
  typedef std::function<bool(unsigned char* data, size_t* read_data, const size_t max_size, const size_t total_read)> RequestCallback;

  struct FormDataItem {
    std::string name;

    // Only one of the following two are required
    std::string value = "";
    RequestCallback value_callback = nullptr;

    // When value_callback is set (if one is missing an exception will be thrown):
    std::string filename = "";
    std::string content_type = "";
    size_t content_length = pockethttp::Buffer::error; /** Needed only when use_chunked_transfer_encoding is false */
  };

  enum FormDataItemStateEnum {
    FORMDATA_HEADER,
    FORMDATA_DATA,
    FORMDATA_ENDING_CRLF,
    FORMDATA_LAST_BOUNDARY,
  };

  struct FormDataItemState {
    FormDataItemStateEnum state = FORMDATA_HEADER;
    size_t remaining = 0;
    size_t total_sent = 0;
    std::string header;
    std::vector<FormDataItem>::iterator item;
  };

  struct FormDataRequest {
    std::string method;
    std::string url;
    Headers headers;
    std::vector<FormDataItem> form_data;
  };

  struct Request {
    std::string method;
    std::string url;
    Headers headers;

    // Only one of the following two are required
    std::string body = "";
    RequestCallback body_callback = nullptr;
  };

  struct Remote {
    std::string protocol;
    std::string host;
    std::string path;
    uint16_t port;
  };

  struct FormDataSendState {
    std::vector<FormDataItem>::iterator current_item;
    unsigned short current_line = 1;
    size_t current_offset = 0;
    bool sending_last_boundary = false;
    size_t last_boundary_offset = 0;
  };

  namespace utils {

    Remote parseUrl(const std::string& url);
    std::string getProtocol(const std::string& url);
    
  } // namespace utils

} // namespace pockethttp

#endif // POCKET_HTTP_REQUEST_HPP

// pockethttp/Response.hpp
#ifndef POCKET_HTTP_RESPONSE_HPP
#define POCKET_HTTP_RESPONSE_HPP

// #include "pockethttp/Headers.hpp"
#include <string>
#include <vector>
#include <functional>

#define POCKETHTTP_RESPONSE_MAX_STATUS_TEXT_SIZE 16

namespace pockethttp {

  enum ChunkedStatus {
    CHUNKED_STATUS_HEX,
    CHUNKED_STATUS_LF,
    CHUNKED_STATUS_DATA,
    CHUNKED_STATUS_POSTLF,
    CHUNKED_STATUS_DONE,
    CHUNKED_STATUS_ERROR
  };

  struct ChunkedResponseState {
    ChunkedStatus status = CHUNKED_STATUS_HEX;
    size_t content_length = 0;
    size_t remaining_content_length = 0;
    unsigned char hexindex = 0;
    char hexbuffer[POCKETHTTP_RESPONSE_MAX_STATUS_TEXT_SIZE + 1];
  };

  struct Response {
      std::string version; // HTTP version, e.g., "HTTP/1.1"

      uint16_t status;
      std::string statusText;
      
      Headers headers;

      std::function<void(const unsigned char* buffer, const size_t& size)> body_callback = nullptr;
  };

} // namespace pockethttp

#endif // POCKET_HTTP_RESPONSE_HPP

// pockethttp/Sockets/SocketWrapper.hpp
#ifndef POCKET_HTTP_SOCKETWRAPPER_HPP
#define POCKET_HTTP_SOCKETWRAPPER_HPP

#include <string>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef int socklen_t;
#else
  #include <unistd.h>
  typedef int SOCKET;
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR (-1)
  #define closesocket(s) close(s)
#endif

namespace pockethttp {

#ifdef _WIN32
  class WinSockManager {
    public:
      static WinSockManager& getInstance();
      bool isInitialized() const;

    private:
      WinSockManager();
      ~WinSockManager();
      WinSockManager(const WinSockManager&) = delete;
      WinSockManager& operator=(const WinSockManager&) = delete;
      bool initialized_ = false;
  };
#endif

  class SocketWrapper {
    public:
      virtual ~SocketWrapper() = default;

      // Conection
      virtual bool connect(const std::string& host, int port) = 0;
      virtual void disconnect() = 0;

      // Sending and receiving data
      virtual size_t send(const unsigned char* buffer, const size_t size) = 0;
      virtual size_t receive(unsigned char* buffer, size_t size, const int64_t& timeout) = 0;

      // Utility methods
      virtual bool isConnected() = 0;
      virtual int64_t getTimestamp() const = 0;
    
    protected:
      SOCKET socket_fd_ = INVALID_SOCKET;
      int64_t last_used_timestamp_ = 0;
      bool connected_ = false;

      bool openTCPSocket(const std::string& host, int port);
  };

} // namespace pockethttp

#endif // POCKET_HTTP_SOCKETWRAPPER_HPP

// pockethttp/Sockets/TCPSocket.hpp
#ifndef POCKET_HTTP_TCPSOCKET_HPP
#define POCKET_HTTP_TCPSOCKET_HPP

// #include "pockethttp/Sockets/SocketWrapper.hpp"
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
typedef int SOCKET;
#endif

namespace pockethttp {

  class TCPSocket : public pockethttp::SocketWrapper {
    public:
      TCPSocket();
      ~TCPSocket() override;

      bool connect(const std::string& host, int port) override;
      void disconnect() override;

      size_t send(const unsigned char* buffer, const size_t size) override;
      size_t receive(unsigned char* buffer, size_t size, const int64_t& timeout) override;

      bool isConnected() override;
      int64_t getTimestamp() const override;
  };

} // namespace pockethttp

#endif // POCKET_HTTP_TCPSOCKET_HPP

// pockethttp/Sockets/TLSSocket.hpp
#ifndef POCKET_HTTP_TLS_SOCKET_HPP
#define POCKET_HTTP_TLS_SOCKET_HPP

// #include "pockethttp/Sockets/SocketWrapper.hpp"

#ifdef USE_POCKET_HTTP_BEARSSL

#include <cstdint>
#include <string>

// Include BearSSL headers directly instead of forward declarations
#include <bearssl/bearssl.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
typedef int SOCKET;
#endif

namespace pockethttp {

  class TLSSocket : public SocketWrapper {
    private:
      br_x509_trust_anchor* trust_anchors_;
      size_t trust_anchors_count_;

      // BearSSL contexts - using raw pointers instead of unique_ptr for
      // incomplete types
      br_ssl_client_context* ssl_client_;
      br_x509_minimal_context* x509_context_;
      br_sslio_context* sslio_context_;
      unsigned char* iobuf_;

      // BearSSL I/O callbacks
      static int sock_read(void* ctx, unsigned char* buf, size_t len);
      static int sock_write(void* ctx, const unsigned char* buf, size_t len);

      // Helper methods
      bool loadCerts();
      bool initializeTLS(const std::string& hostname);
      bool performTLSHandshake(const std::string& hostname);
      void cleanupTLS();

    public:
      TLSSocket();
      ~TLSSocket() override;

      bool connect(const std::string& host, int port) override;
      void disconnect() override;

      size_t send(const unsigned char* buffer, const size_t size) override;
      size_t receive(unsigned char* buffer, size_t size, const int64_t& timeout) override;
      
      bool isConnected() override;
      int64_t getTimestamp() const override;
  };

} // namespace pockethttp

#endif // USE_POCKET_HTTP_BEARSSL

#endif // POCKET_HTTP_TLS_SOCKET_HPP

// pockethttp/Sockets/SocketPool.hpp
#ifndef POCKET_HTTP_SOCKET_POOL_HPP
#define POCKET_HTTP_SOCKET_POOL_HPP

// #include "pockethttp/Logs.hpp"
// #include "pockethttp/Timestamp.hpp"
// #include "pockethttp/Sockets/SocketWrapper.hpp"
#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <functional>

namespace pockethttp {

  using SocketCreator = std::function<std::shared_ptr<pockethttp::SocketWrapper>()>;

  class SocketPool {
    private:
      static std::map<std::string, pockethttp::SocketCreator> protocols_;
      static std::map<std::string, std::vector<std::shared_ptr<pockethttp::SocketWrapper>>> pool_;

      static std::string buildPoolKey(const std::string& protocol, const std::string& host, const uint16_t port) {
        pockethttp_log("[SocketPool] buildPoolKey" << protocol << ":" << port);
        return protocol + ":" + host + ":" + std::to_string(port);
      }

      static std::shared_ptr<pockethttp::SocketWrapper> findAvailableSocket(std::vector<std::shared_ptr<pockethttp::SocketWrapper>>& connections) {
        pockethttp_log("[SocketPool] findAvailableSocket: searching for available socket");

        for (auto& conn : connections) {
          if (conn.use_count() == 1 && conn->isConnected()) {
            pockethttp_log("[SocketPool] findAvailableSocket: found available socket");
            return conn;
          }
        }

        pockethttp_log("[SocketPool] findAvailableSocket: no available socket found");
        return nullptr;
      }

      static std::shared_ptr<pockethttp::SocketWrapper> createNewSocket(const std::string& protocol, const std::string& host, const uint16_t port) {
        pockethttp_log("[SocketPool] createNewSocket: creating new socket for " << host << ":" << port);
        
        auto socketCreator = protocols_.find(protocol);
        if (socketCreator == protocols_.end()) {
          pockethttp_log("[SocketPool] createNewSocket: protocol not found: " << protocol);
          return nullptr;
        }

        auto newSocket = socketCreator->second();
        if (newSocket->connect(host, port)) {
          pockethttp_log("[SocketPool] createNewSocket: connection successful");
          return newSocket;
        } else {
          pockethttp_log("[SocketPool] createNewSocket: connection failed");
          return nullptr;
        }
      }

    public:
      static std::shared_ptr<pockethttp::SocketWrapper> getSocket(const std::string& protocol, const std::string& host, uint16_t port) {
        pockethttp_log("[SocketPool] getSocket: protocol=" << protocol << ", host=" << host << ", port=" << port);
        cleanupUnused();

        const std::string key = buildPoolKey(protocol, host, port);
        auto& connections = pool_[key];

        // Try to reuse existing connection
        if (auto socket = findAvailableSocket(connections)) {
          pockethttp_log("[SocketPool] getSocket: reusing existing socket");
          return socket;
        }

        // Create new connection
        if (auto newSocket = createNewSocket(protocol, host, port)) {
          connections.push_back(newSocket);
          pockethttp_log("[SocketPool] getSocket: new socket created and added to pool");
          return newSocket;
        }

        pockethttp_log("[SocketPool] getSocket: failed to get socket");
        return nullptr;
      }

      static void registerProtocol(const std::string& protocol, pockethttp::SocketCreator creator) {
        pockethttp_log("[SocketPool] registerProtocol: protocol=" << protocol);
        protocols_[protocol] = creator;
      }

      static void cleanupUnused(int64_t timeout = 30000) {
        pockethttp_log("[SocketPool] cleanupUnused: cleaning up unused connections");
        const int64_t currentTime = pockethttp::Timestamp::getCurrentTimestamp();

        for (auto& [key, connections] : pool_) {
          connections.erase(
            std::remove_if(connections.begin(), connections.end(),
              [timeout, currentTime] (std::shared_ptr<pockethttp::SocketWrapper>& conn) {
                const int64_t connectionAge = currentTime - conn->getTimestamp();
                const bool shouldRemove =
                  (conn.use_count() == 1 && connectionAge > timeout) ||
                  !conn->isConnected();

                if (shouldRemove) {
                  pockethttp_log("[SocketPool] cleanupUnused: disconnecting socket");
                  conn->disconnect();
                }
                
                return shouldRemove;
              }),
            connections.end()
          );
        }
      }

      static void cleanupAll() {
        pockethttp_log("[SocketPool] cleanupAll: disconnecting all sockets and clearing pool");
        
        for (auto& [key, connections] : pool_) {
          for (auto& conn : connections) {
            conn->disconnect();
          }
        }
        
        pool_.clear();
      }

      static size_t getPoolSize() {
        size_t totalConnections = 0;
        for (const auto& [key, connections] : pool_) {
          totalConnections += connections.size();
        }
        return totalConnections;
      }

      static size_t getPoolCount() {
        return pool_.size();
      }
  };

} // namespace pockethttp

#endif

// pockethttp/Http.hpp
#ifndef POCKET_HTTP_HTTP_HPP
#define POCKET_HTTP_HTTP_HPP

// #include "pockethttp/Request.hpp"
// #include "pockethttp/Response.hpp"
// #include "pockethttp/Sockets/SocketWrapper.hpp"

namespace pockethttp {

  class Http {
    private:
      int64_t timeout_;
      bool request(
        pockethttp::Remote& remote,
        std::string& method,
        pockethttp::Headers& headers,
        pockethttp::Response& response,
        RequestCallback& body_callback
      );

      void setDefaultHeaders(pockethttp::Headers& headers, pockethttp::Remote& remote);
      std::string generateBoundary();

      size_t parseStatusLine(
        pockethttp::Response& response, 
        std::shared_ptr<SocketWrapper> socket, 
        unsigned char* buffer, 
        const size_t& buffer_size,
        size_t& total_bytes_read
      );

      size_t parseHeaders(
        pockethttp::Response& response, 
        std::shared_ptr<SocketWrapper> socket, 
        unsigned char* buffer, 
        const size_t& buffer_size,
        size_t& prev_data_size
      );

      bool handleChunked(
        pockethttp::Response& response, 
        std::shared_ptr<SocketWrapper> socket,
        std::function<void(unsigned char* buffer, size_t& size)> body_callback,
        unsigned char* buffer,
        size_t& prev_data_size
      );

    public:
      Http();
      Http(int64_t timeout);
      ~Http();

      bool request(pockethttp::Request& req, pockethttp::Response& res);
      bool request(pockethttp::FormDataRequest& req, pockethttp::Response& res);
  };
  
} // namespace pockethttp

#endif // POCKET_HTTP_HTTP_HPP

