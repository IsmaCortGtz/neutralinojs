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

// Auto-generated merged cpp
#if __has_include("pockethttp.hpp")
  #include "pockethttp.hpp"
#elif __has_include("pockethttp/pockethttp.hpp")
  #include "pockethttp/pockethttp.hpp"
#else
  #error "Cannot find pockethttp.hpp"
#endif

// pockethttp/Buffer.cpp
// #include "pockethttp/Buffer.hpp"
#include <cstddef>
#include <cstring>

namespace pockethttp {

  namespace Buffer {

    size_t find(const unsigned char* buffer, const size_t& size, const unsigned char* to_find, const size_t& to_find_size) {
      if (buffer == nullptr || size == 0 || to_find == nullptr || to_find_size == 0) {
        return pockethttp::Buffer::error; // No data to search
      }

      if (size < to_find_size) {
        return pockethttp::Buffer::error; // Not enough data to find the pattern
      }

      for (size_t i = 0; i <= size - to_find_size; ++i) {
        if (std::memcmp(buffer + i, to_find, to_find_size) == 0) {
          return i;
        }
      }

      return pockethttp::Buffer::error; // Not found
    }

    bool equal(const unsigned char* buffer, const unsigned char* to_find, const size_t& size) {
      if (buffer == nullptr || to_find == nullptr || size == 0) {
        return false; // Invalid input
      }
      return std::memcmp(buffer, to_find, size) == 0;
    }

  } // namespace Buffer

} // namespace pockethttp

// pockethttp/Timestamp.cpp
// #include "pockethttp/Timestamp.hpp"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace pockethttp {

  namespace Timestamp {

    int64_t getCurrentTimestamp() {
      auto now = std::chrono::system_clock::now();
      auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
          now.time_since_epoch())
                        .count();
      return millis;
    }

    std::string getFormatedTimestamp() {
      auto now = std::chrono::system_clock::now();
      std::time_t now_c = std::chrono::system_clock::to_time_t(now);
      std::tm *parts = std::localtime(&now_c);
      std::ostringstream oss;

      // get 10-digit milliseconds
      auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
          now.time_since_epoch())
                        .count() % 1'000'000'000;
      oss << std::put_time(parts, "%Y-%m-%d %H:%M:%S");
      oss << "." << std::setfill('0') << std::setw(3) << ns;
      return oss.str();
    }

  } // namespace Timestamp

} // namespace pockethttp

// pockethttp/Decompress.cpp
// #include "pockethttp/Logs.hpp"
// #include "pockethttp/Decompress.hpp"

#if __has_include("miniz.h")
  #include <miniz.h>
#elif __has_include("miniz/miniz.h")
  #include <miniz/miniz.h>
#else
  #error "Cannot find miniz.h or miniz/miniz.h"
#endif

extern "C" {
#if __has_include("brotli/decode.h")
  #include <brotli/decode.h>
#elif __has_include("brotli/brotli/decode.h")
  #include <brotli/brotli/decode.h>
#else
  #error "Cannot find brotli/decode.h"
#endif
}

#include <stdexcept>
#include <iostream>
#include <functional>
#include <cstddef>
#include <cstdint>

namespace pockethttp {

  Decompressor::Decompressor(DecompressionAlgorithm algorithm) : algorithm(algorithm) {}

  Decompressor::~Decompressor() {
    pockethttp_log("[Decompressor] Cleaning up decompressor");
    if (
      this->algorithm == DecompressionAlgorithm::DEFLATE ||
      this->algorithm == DecompressionAlgorithm::GZIP
    ) {
      mz_inflateEnd(&this->stream);
    }

    if (
      this->algorithm == DecompressionAlgorithm::BROTLI &&
      this->brotli_state
    ) {
      BrotliDecoderDestroyInstance(this->brotli_state);
      this->brotli_state = nullptr;
    }
  }

  DecompressionState Decompressor::init() {
    if (this->algorithm == DecompressionAlgorithm::BROTLI) {
      this->brotli_state = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);

      if (!this->brotli_state) this->state = DecompressionState::DECOMPRESS_ERROR;
      else this->state = DecompressionState::INITIALIZED;

    } else if (this->algorithm == DecompressionAlgorithm::DEFLATE || this->algorithm == DecompressionAlgorithm::GZIP) {
      
      memset(&this->stream, 0, sizeof(this->stream));
      int window_bits = this->algorithm == DecompressionAlgorithm::GZIP ? -MZ_DEFAULT_WINDOW_BITS : MZ_DEFAULT_WINDOW_BITS;
      
      int ret = mz_inflateInit2(&this->stream, window_bits);
      if (ret != MZ_OK) {
        pockethttp_error("[Decompressor] Failed to initialize decompressor: " << ret);
        return DecompressionState::DECOMPRESS_ERROR;
      }

      pockethttp_log("[Decompressor] Decompressor initialized successfully: " << ret);

      this->state = DecompressionState::INITIALIZED;
    } else {
      this->state = DecompressionState::DECOMPRESS_ERROR;
    }

    return this->state;
  }

  size_t Decompressor::get_gzip_header_length(const uint8_t* data, size_t size) {
    // The minimum length of a GZIP header is 10 bytes.
    if (size < 10) return 0;

    // Check GZIP magic numbers (0x1f 0x8b)
    if (data[0] != 0x1f || data[1] != 0x8b) return 0;

    // The compression method must be DEFLATE (8)
    if (data[2] != 8) return 0;

    const uint8_t flags = data[3];
    size_t header_len = 10;

    // FEXTRA: Extra field
    if (flags & 0x04) {
      if (header_len + 2 > size) return 0; // Incomplete
      uint16_t extra_len = data[header_len] | (data[header_len + 1] << 8);
      header_len += 2 + extra_len;
    }

    // FNAME: File name (null-terminated)
    if (flags & 0x08) {
      while (header_len < size && data[header_len] != 0) {
        header_len++;
      }
      if (header_len < size) header_len++; // Include the NUL
    }

    // FCOMMENT: Comment (null-terminated)
    if (flags & 0x10) {
      while (header_len < size && data[header_len] != 0) {
          header_len++;
      }
      if (header_len < size) header_len++; // Include the NUL
    }
    // FHCRC: CRC16 of the header
    if (flags & 0x02) {
      header_len += 2;
    }

    return (header_len <= size) ? header_len : 0;
  }

  DecompressionState Decompressor::decompress(
    const unsigned char* input, 
    size_t input_size, 
    std::function<void(const unsigned char* buffer, const size_t& size)> output_callback
  ) {
    pockethttp_log("[Decompressor] Decompress called with " << input_size << " bytes of input data.");
    if (input == nullptr || input_size == 0) {
      this->state = DecompressionState::DECOMPRESS_ERROR;
      return this->state;
    }

    if (this->algorithm == DecompressionAlgorithm::BROTLI) {
      size_t available_in = input_size;
      const uint8_t* next_in = input;
      unsigned char output[POCKET_HTTP_DECOMPRESS_OUTPUT_CHUNK_SIZE];

      while (true) {
        size_t available_out = POCKET_HTTP_DECOMPRESS_OUTPUT_CHUNK_SIZE;
        uint8_t* next_out = output;

        BrotliDecoderResult result = BrotliDecoderDecompressStream(
          this->brotli_state,  
          &available_in, &next_in,
          &available_out, &next_out,
          nullptr
        );  
              
        size_t output_size = POCKET_HTTP_DECOMPRESS_OUTPUT_CHUNK_SIZE - available_out;
        if (output_size > 0) output_callback(output, output_size);

        if (result == BROTLI_DECODER_RESULT_SUCCESS) {
          this->state = DecompressionState::FINISHED;
          break;
        }
        
        if (result == BROTLI_DECODER_RESULT_ERROR) {
          this->state = DecompressionState::DECOMPRESS_ERROR;
          break;
        }

        if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) break;
        if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) continue;
      }

      return this->state;
    }

    size_t header_length = this->algorithm == DecompressionAlgorithm::GZIP && !this->header_processed ? this->get_gzip_header_length(input, input_size) : 0;
    if (header_length > 0) this->header_processed = true;
    pockethttp_log("[Decompressor] GZIP header length: " << header_length << "/" << input_size << " bytes.");

    size_t out_size = 0;
    this->stream.next_in = input + header_length;
    this->stream.avail_in = input_size - header_length;
    this->state = DecompressionState::DECOMPRESSING;

    pockethttp_log("[Decompressor] Decompressing " << this->stream.avail_in << " bytes of data.");

    unsigned char output[POCKET_HTTP_DECOMPRESS_OUTPUT_CHUNK_SIZE];
    bool done = false;

    while(!done) {
      done = true;
      int status;

      this->stream.next_out = output;
      this->stream.avail_out = POCKET_HTTP_DECOMPRESS_OUTPUT_CHUNK_SIZE;

      status = mz_inflate(&this->stream, MZ_NO_FLUSH);
      pockethttp_log("[Decompressor] mz_inflate status: " << status);

      if (this->stream.avail_out != POCKET_HTTP_DECOMPRESS_OUTPUT_CHUNK_SIZE) {
        if (status == MZ_OK || status == MZ_STREAM_END) {
          out_size = POCKET_HTTP_DECOMPRESS_OUTPUT_CHUNK_SIZE - this->stream.avail_out;
          output_callback(output, out_size);
        }
      }

      switch (status) {
        case MZ_OK:
          done = false;
          this->state = DecompressionState::DECOMPRESSING;
          break;
        case MZ_BUF_ERROR:
          done = true;
          this->state = DecompressionState::DECOMPRESSING;
          break;
        case MZ_STREAM_END:
          done = true;
          this->state = DecompressionState::FINISHED;
          break;
        default:
          pockethttp_error("[Decompressor] Decompression error: " << status);
          done = true;
          this->state = DecompressionState::DECOMPRESS_ERROR;
          break;
      }
    }
    
    return this->state;
  }

  const uint8_t* Decompressor::getPendingInputPtr() const {
    return this->stream.next_in;
  }

  size_t Decompressor::getPendingInputSize() const {
    return this->stream.avail_in;
  }

} // namespace pockethttp

// pockethttp/Headers.cpp
// #include "pockethttp/Buffer.hpp"
// #include "pockethttp/Headers.hpp"
#include <algorithm>
#include <map>
#include <string>
#include <vector>

namespace pockethttp {

  Headers Headers::parse(const std::string& rawHeaders) {
    Headers headers;

    std::vector<std::string> lines;
    size_t start = 0;
    size_t end = rawHeaders.find("\r\n");
    while (end != std::string::npos) {
      lines.push_back(rawHeaders.substr(start, end - start));
      start = end + 2;
      end = rawHeaders.find("\r\n", start);
    }
    lines.push_back(rawHeaders.substr(start));

    for (const std::string& line : lines) {
      size_t colonPos = line.find(':');
      if (colonPos != std::string::npos) {
        std::string key = line.substr(0, colonPos);
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        std::string value = line.substr(colonPos + 1);

        value.erase(0, value.find_first_not_of(' '));
        headers.set(key, value);
      }
    }

    return headers;
  }

  void Headers::load(const std::string& rawHeaders) {
    std::vector<std::string> lines;
    size_t start = 0;
    size_t end = rawHeaders.find("\r\n");
    while (end != std::string::npos) {
      lines.push_back(rawHeaders.substr(start, end - start));
      start = end + 2;
      end = rawHeaders.find("\r\n", start);
    }
    lines.push_back(rawHeaders.substr(start));

    for (const std::string& line : lines) {
      size_t colonPos = line.find(':');
      if (colonPos != std::string::npos) {
        std::string key = line.substr(0, colonPos);
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        std::string value = line.substr(colonPos + 1);

        value.erase(0, value.find_first_not_of(' '));
        this->set(key, value);
      }
    }
  }

  void Headers::set(const std::string& key, const std::string& value) {
    std::string lowerKey = key;
    std::transform(
        lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    headers_[lowerKey] = value;
  }

  std::string Headers::get(const std::string& key) const {
    std::string lowerKey = key;
    std::transform(
        lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    auto it = headers_.find(lowerKey);
    return (it != headers_.end()) ? it->second : "";
  }

  bool Headers::has(const std::string& key) const {
    std::string lowerKey = key;
    std::transform(
        lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    return headers_.find(lowerKey) != headers_.end();
  }

  void Headers::remove(const std::string& key) {
    std::string lowerKey = key;
    std::transform(
        lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    headers_.erase(lowerKey);
  }

  std::string Headers::dump() const {
    std::string result;
    for (const auto& header : headers_) {
      result += header.first + ": " + header.second + "\r\n";
    }

    return result;
  }

  std::vector<std::string> Headers::keys() const {
    std::vector<std::string> keys;
    for (const auto& header : headers_) {
      keys.push_back(header.first);
    }
    return keys;
  }

} // namespace pockethttp

// pockethttp/Request.cpp
// #include "pockethttp/Request.hpp"
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>
#include <functional>


namespace pockethttp {

  namespace utils {

    Remote parseUrl(const std::string& url) {
      Remote remote;

      if (url.empty()) {
        throw std::invalid_argument("URL cannot be empty");
      }

      // Regex para parsear URL completa
      // Captura: protocol://host:port/path
      std::regex urlRegex(R"(^(https?):\/\/([^:\/\s]+)(?::(\d+))?(\/.*)?$)");
      std::smatch matches;

      if (!std::regex_match(url, matches, urlRegex)) {
        throw std::invalid_argument("Invalid URL format");
      }

      // Extraer componentes
      remote.protocol = matches[1].str();
      remote.host = matches[2].str();

      // Puerto - usar default si no está especificado
      if (matches[3].matched) {
        remote.port = static_cast<uint16_t>(std::stoi(matches[3].str()));
      } else {
        // Puerto por defecto según protocolo
        if (remote.protocol == "https") {
          remote.port = 443;
        } else if (remote.protocol == "http") {
          remote.port = 80;
        } else {
          throw std::invalid_argument("Unsupported protocol: " + remote.protocol);
        }
      }

      // Path - usar "/" si no está especificado
      if (matches[4].matched) {
        remote.path = matches[4].str();
      } else {
        remote.path = "/";
      }

      return remote;
    }

    std::string getProtocol(const std::string& url) {
      std::regex protocolRegex(R"(^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/)");
      std::smatch match;

      if (std::regex_search(url, match, protocolRegex)) {
        return match[1].str();
      } else {
        throw std::invalid_argument("URL does not contain a valid protocol");
      }
    }

    std::string url_encode(const std::string& decoded, const std::string& safe) {
      std::string out;
      char hexChars[] = "0123456789ABCDEF";

      for (unsigned char c : decoded) {
        if (isalnum(c) || safe.find(c) != std::string::npos) {
          out += c;
        } else if (c == ' ') {
          out += '+';
        } else {
          out += '%';
          out += hexChars[(c >> 4) & 0x0F];
          out += hexChars[c & 0x0F];
        }
      }

      return out;
    }

    std::string url_decode(const std::string& encoded) {
      std::string out;
      
      for (size_t i = 0; i < encoded.size(); ++i) {
        if (encoded[i] == '%' && i + 2 < encoded.size()) {
          std::string hex = encoded.substr(i + 1, 2);
          out += static_cast<char>(std::stoi(hex, nullptr, 16));
          i += 2;
        } else if (encoded[i] == '+') {
          out += ' ';
        } else {
          out += encoded[i];
        }
      }

      return out;
    }

    std::string normalize_url(const std::string &raw_url) {
      // Replace spaces with %20
      std::string url = url_decode(raw_url);
      size_t pos = 0;
      while ((pos = url.find(' ', pos)) != std::string::npos) {
        url.replace(pos, 1, "%20");
        pos += 3; // Move past the inserted %20
      }

      return url;
    }

  } // namespace utils

} // namespace pockethttp

// pockethttp/SystemCerts.cpp
// #include "pockethttp/SystemCerts.hpp"
// #include "pockethttp/Logs.hpp"
// #include "pockethttp/Buffer.hpp"

// #include "pockethttp/Sockets/certs.hpp"

#ifdef USE_POCKET_HTTP_BEARSSL
  #if __has_include("bearssl.h")
    #include <bearssl.h>
  #elif __has_include("bearssl/bearssl.h")
    #include <bearssl/bearssl.h>
  #else
    #error "Cannot find bearssl.h or bearssl/bearssl.h"
  #endif
#endif // USE_POCKET_HTTP_BEARSSL

#if __has_include("base64.hpp")
  #include <base64.hpp>
#elif __has_include("base64/base64.hpp")
  #include <base64/base64.hpp>
#else
  #error "Cannot find base64.hpp or base64/base64.hpp"
#endif

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstring>
#include <algorithm>
#include <cstdlib>

#if defined(_WIN32)
  #include <windows.h>
  #include <wincrypt.h>
  #pragma comment(lib, "crypt32.lib")
#elif defined(__APPLE__)
  #include <Security/Security.h>
  #include <CoreFoundation/CoreFoundation.h>
#endif


#if defined(__linux__) || defined(__FreeBSD__)
const std::string SYSTEM_CERT_DIRS[] = {
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
    "/etc/pki/ca-trust/extracted/pem",
    "/usr/share/ca-certificates",
    "/usr/share/pki/ca-trust-source",
    "/usr/share/ca-certs"
};
#endif

namespace pockethttp {

  namespace Certificates {

    std::vector<std::vector<unsigned char>> pem2Der(const std::string &pem) {
      std::vector<std::vector<unsigned char>> der_list;
      size_t pos = 0;

      while ((pos = pem.find("-----BEGIN CERTIFICATE-----", pos)) != std::string::npos) {
        size_t end = pem.find("-----END CERTIFICATE-----", pos);
        if (end == std::string::npos) break;

        size_t b64_start = pos + strlen("-----BEGIN CERTIFICATE-----");
        std::string b64_block = pem.substr(b64_start, end - b64_start);

        // Eliminar cualquier carácter que no sea Base64
        b64_block.erase(
          std::remove_if(b64_block.begin(), b64_block.end(),
          [](char c){ return !isalnum(c) && c != '+' && c != '/' && c != '='; }),
          b64_block.end()
        );

        // Decodificar Base64
        std::string decoded = base64::from_base64(b64_block);
        std::vector<unsigned char> der(decoded.begin(), decoded.end());
        pos = end + strlen("-----END CERTIFICATE-----");
        if (der.empty() || !isDER(der)) {
          pockethttp_error("[SystemCerts] Failed to decode PEM certificate.");
          continue;
        }

        der_list.push_back(der);
      }

      return der_list;
    }

    bool isDER(std::vector<unsigned char>& cert) {
      unsigned char* buf = cert.data();
      int fb;
      size_t dlen, len = cert.size();

      if (len < 2) return false;
      if (*buf++ != 0x30) return false;

      fb = *buf++;
      len -= 2;
      if (fb < 0x80) {
        return (size_t)fb == len;
      } else if (fb == 0x80) {
        return false;
      } else {
        fb -= 0x80;
        if (len < (size_t)fb + 2) return false;

        len -= (size_t)fb;
        dlen = 0;
        while (fb-- > 0) {
          if (dlen > (len >> 8)) return false;
          dlen = (dlen << 8) + (size_t)*buf++;
        }
        return dlen == len;
      }
    }

    #ifdef USE_POCKET_HTTP_BEARSSL
      void dn_append(void *ctx, const void *data, size_t len) {
        auto vector = static_cast<std::vector<unsigned char>*>(ctx);
        vector->insert(
          vector->end(), 
          static_cast<const unsigned char*>(data), 
          static_cast<const unsigned char*>(data) + len
        );
      }

      bool der2Anchor(const std::vector<unsigned char>& der, br_x509_trust_anchor *ta) {
        br_x509_decoder_context dc;
        br_x509_pkey *pk;
        std::vector<unsigned char> dn_buf;

        br_x509_decoder_init(&dc, dn_append, &dn_buf);
        br_x509_decoder_push(&dc, der.data(), der.size());
        pk = br_x509_decoder_get_pkey(&dc);

        if (!pk) {
          pockethttp_error("[SystemCerts] Failed to decode certificate.");
          return false;
        }

        ta->dn.data = (unsigned char*)malloc(dn_buf.size());
        if (!ta->dn.data) {
          pockethttp_error("[SystemCerts] Memory allocation failed.");
          return false;
        }

        std::memcpy(ta->dn.data, dn_buf.data(), dn_buf.size());
        ta->dn.len = dn_buf.size();
        dn_buf.clear();

        ta->flags = 0;
        if (br_x509_decoder_isCA(&dc)) ta->flags |= BR_X509_TA_CA;
        
        switch (pk->key_type) {
          case BR_KEYTYPE_RSA:
            ta->pkey.key_type = BR_KEYTYPE_RSA;

            ta->pkey.key.rsa.n = (unsigned char*)malloc(pk->key.rsa.nlen);
            if (!ta->pkey.key.rsa.n) {
              pockethttp_error("[SystemCerts] Memory allocation failed.");
              free(ta->dn.data);
              return false;
            }
            std::memcpy(ta->pkey.key.rsa.n, pk->key.rsa.n, pk->key.rsa.nlen);

            ta->pkey.key.rsa.e = (unsigned char*)malloc(pk->key.rsa.elen);
            if (!ta->pkey.key.rsa.e) {
              pockethttp_error("[SystemCerts] Memory allocation failed.");
              free(ta->dn.data);
              free(ta->pkey.key.rsa.n);
              return false;
            }
            std::memcpy(ta->pkey.key.rsa.e, pk->key.rsa.e, pk->key.rsa.elen);

            ta->pkey.key.rsa.elen = pk->key.rsa.elen;
            break;

          case BR_KEYTYPE_EC:
            ta->pkey.key_type = BR_KEYTYPE_EC;
            ta->pkey.key.ec.curve = pk->key.ec.curve;
            ta->pkey.key.ec.q = (unsigned char*)malloc(pk->key.ec.qlen);
            if (!ta->pkey.key.ec.q) {
              pockethttp_error("[SystemCerts] Memory allocation failed.");
              free(ta->dn.data);
              return false;
            }
            std::memcpy(ta->pkey.key.ec.q, pk->key.ec.q, pk->key.ec.qlen);
            ta->pkey.key.ec.qlen = pk->key.ec.qlen;
            break;

          default:
            pockethttp_error("[SystemCerts] Unsupported public key type in CA.");
            free(ta->dn.data);
            return false;
        }

        return true;
      }
    #endif // USE_POCKET_HTTP_BEARSSL

  } // namespace Certificates

  // Public
  std::vector<std::vector<unsigned char>> SystemCerts::loadSystemCerts() {
    std::vector<std::vector<unsigned char>> der_list;

    #if defined(_WIN32)
      
      pockethttp_log("[SystemCerts] Loading system CA certificates for Windows.");

      auto load_store = [&](LPCWSTR storeName) {
        pockethttp_log("[SystemCerts] Loading from store: " + std::wstring(storeName));
        HCERTSTORE hStore = CertOpenSystemStoreW(NULL, storeName);
        if (!hStore) {
          pockethttp_error("[SystemCerts] Failed to open store: " + std::wstring(storeName));
          return;
        }

        PCCERT_CONTEXT pCertContext = nullptr;
        while ((pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)) != nullptr) {
          std::vector<unsigned char> certBuf(
            pCertContext->pbCertEncoded,
            pCertContext->pbCertEncoded + pCertContext->cbCertEncoded
          );
          
          if (!certBuf.empty() && pockethttp::Certificates::isDER(certBuf)) {
            der_list.push_back(std::move(certBuf));
          }
        }

        CertCloseStore(hStore, 0);
      };
      
      load_store(L"ROOT");       // Trusted Root Certification Authorities
      load_store(L"CA");         // Intermediate Certification Authorities
      load_store(L"MY");         // Personal
      load_store(L"AuthRoot");   // Third-Party Root Certification Authorities
    
    #elif defined(__APPLE__)

      pockethttp_log("[SystemCerts] Loading system CA certificates for macOS.");
      auto loadFromKeychain = [&](SecKeychainRef keychain) {
        CFArrayRef searchList = CFArrayCreate(nullptr, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);

        const void *keys[]   = { kSecClass, kSecReturnRef, kSecMatchLimit, kSecMatchSearchList };
        const void *values[] = { kSecClassCertificate, kCFBooleanTrue, kSecMatchLimitAll, searchList };

        CFDictionaryRef query = CFDictionaryCreate(nullptr, keys, values, 4,
                                                   &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

        CFArrayRef certsArray = nullptr;
        OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&certsArray);
        CFRelease(query);
        CFRelease(searchList);

        if (status == errSecItemNotFound) {
          pockethttp_log("[SystemCerts] No certificates found in the specified keychain.");
          return;
        }

        if (status != errSecSuccess || !certsArray) {
          pockethttp_error("[SystemCerts] Failed to retrieve certificates from current keychain.");
          return;
        }

        CFIndex count = CFArrayGetCount(certsArray);
        for (CFIndex i = 0; i < count; i++) {
          SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certsArray, i);
          if (!cert) continue;

          CFDataRef certData = SecCertificateCopyData(cert);
          if (!certData) continue;

          const UInt8 *bytes = CFDataGetBytePtr(certData);
          CFIndex len = CFDataGetLength(certData);
          std::vector<unsigned char> buf(bytes, bytes + len);

          if (buf.empty() || !pockethttp::Certificates::isDER(buf)) {
            pockethttp_error("[SystemCerts] Invalid DER certificate found, skipping.");
            CFRelease(certData);
            continue;
          }

          der_list.push_back(std::move(buf));
          CFRelease(certData);
        }

        CFRelease(certsArray);
      };
    
      // System Roots from Apple
      SecKeychainRef rootsKeychain = nullptr;
      if (SecKeychainOpen("/System/Library/Keychains/SystemRootCertificates.keychain", &rootsKeychain) == errSecSuccess) {
        pockethttp_log("[SystemCerts] Loading from SystemRootCertificates.keychain");
        loadFromKeychain(rootsKeychain);
        CFRelease(rootsKeychain);
      }

      // System Keychain (CA installed by the system administrator)
      SecKeychainRef systemKC = nullptr;
      if (SecKeychainCopyDomainDefault(kSecPreferencesDomainSystem, &systemKC) == errSecSuccess) {
        pockethttp_log("[SystemCerts] Loading from System Keychain");
        loadFromKeychain(systemKC);
        CFRelease(systemKC);
      }

      // Login Keychain (current user)
      SecKeychainRef loginKC = nullptr;
      if (SecKeychainCopyDomainDefault(kSecPreferencesDomainUser, &loginKC) == errSecSuccess) {
        pockethttp_log("[SystemCerts] Loading from Login Keychain");
        loadFromKeychain(loginKC);
        CFRelease(loginKC);
      }

    #elif defined(__linux__) || defined(__FreeBSD__)
      
      pockethttp_log("[SystemCerts] Loading system CA certificates for Linux/FreeBSD.");
        
      for (const auto& dir : SYSTEM_CERT_DIRS) {
        std::filesystem::path directory(dir);
        if (!std::filesystem::exists(directory)) continue;
        if (!std::filesystem::is_directory(directory)) continue;

        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
          if (!entry.is_regular_file()) continue;

          std::ifstream file(entry.path(), std::ios::binary);
          if (file.fail()) continue;

          std::string pem((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
          file.close();

          if (pem.empty()) continue;

          // Check if the content is already in DER format
          std::vector<unsigned char> pem_buf(pem.begin(), pem.end());
          if (pockethttp::Certificates::isDER(pem_buf)) {
            der_list.push_back(std::move(pem_buf));
            continue;
          }

          // Not DER, clear memory
          pem_buf.clear();
          pem_buf.shrink_to_fit();

          std::vector<std::vector<unsigned char>> der_certs = pockethttp::Certificates::pem2Der(pem);
          if (der_certs.empty()) {
            pockethttp_log("[SystemCerts] No valid PEM certificates found in: " << entry.path());
            continue;
          }

          for (auto& der : der_certs) {
            if (der.empty() || !pockethttp::Certificates::isDER(der)) {
              pockethttp_error("[SystemCerts] Invalid DER certificate found, skipping.");
              continue;
            }

            der_list.push_back(std::move(der));
          }
        }

        break;
      }

    #else

      pockethttp_error("[SystemCerts] System certificate loading not implemented for this OS.");
      return {};

    #endif
    
    pockethttp_log("[SystemCerts] Loaded " << der_list.size() << " CA certificates from the system.");
    return der_list;
  }
    
  #ifdef USE_POCKET_HTTP_BEARSSL
    bool SystemCerts::initialized = false;
    std::vector<br_x509_trust_anchor> SystemCerts::certs;

    br_x509_trust_anchor* SystemCerts::getBearSSLTrustAnchors() {
      if (!initialized) SystemCerts::init();
      return certs.data();
    }

    size_t SystemCerts::getBearSSLTrustAnchorsSize() {
      if (!initialized) SystemCerts::init();
      return certs.size();
    }

    void SystemCerts::cleanup() {
      int end = static_cast<int>(certs.size());

      if (end <= 0) return;
      pockethttp_log("[SystemCerts] Cleaning up " << end << " loaded CA certificates.");

      for (int i = 0; i < end; ++i) {
        br_x509_trust_anchor &ta = certs[i];

        free(ta.dn.data);
        if (ta.pkey.key_type == BR_KEYTYPE_RSA) {
          free(ta.pkey.key.rsa.n);
          free(ta.pkey.key.rsa.e);
        } else if (ta.pkey.key_type == BR_KEYTYPE_EC) {
          free(ta.pkey.key.ec.q);
        }
      }
    }

    void SystemCerts::init() {
      if (!pockethttp::SystemCerts::certs.empty() || pockethttp::SystemCerts::initialized) {
        pockethttp_log("[SystemCerts] Certificates already loaded.");
        return;
      }

      initialized = true;
      std::atexit(pockethttp::SystemCerts::cleanup);

      std::vector<std::vector<unsigned char>> der_list = pockethttp::SystemCerts::loadSystemCerts();
      if (der_list.empty()) {
        pockethttp_log("[SystemCerts] No system certificates loaded.");
      } else {
        for (auto& der : der_list) {
          br_x509_trust_anchor ta;
          if (!pockethttp::Certificates::der2Anchor(der, &ta)) {
            pockethttp_error("[SystemCerts] Failed to convert a certificate to BearSSL format, skipping.");
            continue;
          }

          pockethttp::SystemCerts::certs.push_back(ta);
        }
        pockethttp_log("[SystemCerts] Successfully loaded " << pockethttp::SystemCerts::certs.size() << " BearSSL trust anchors.");
      }

      #ifdef USE_POCKET_HTTP_MOZILLA_ROOT_CERTS
        // Load Mozilla's root CA certificates
        pockethttp_log("[SystemCerts] Loading " << pockethttp::MozillaCA::derCAs.size() << " Mozilla's root CA certificates.");

        for (std::vector<unsigned char>& der : pockethttp::MozillaCA::derCAs) {
          if (!pockethttp::Certificates::isDER(der)) {
            pockethttp_error("[SystemCerts] Invalid DER certificate found in Mozilla's CA list, skipping.");
            continue;
          }
          
          br_x509_trust_anchor ta;
          if (!pockethttp::Certificates::der2Anchor(der, &ta)) {
            pockethttp_error("[SystemCerts] Failed to convert a certificate to BearSSL format, skipping.");
            continue;
          }

          pockethttp::SystemCerts::certs.push_back(ta);
        }
      #endif
    }
  #endif // USE_POCKET_HTTP_BEARSSL

} // namespace pockethttp

// pockethttp/Sockets/SocketWrapper.cpp
// #include "pockethttp/Sockets/SocketWrapper.hpp"
// #include "pockethttp/Logs.hpp"
// #include "pockethttp/Results.hpp"

#include <string>
#include <iostream>
#include <cstring>
#include <stdexcept>
#include <chrono>
#include <vector>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef int socklen_t;
#else
  #include <sys/socket.h>
  #include <sys/ioctl.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>  
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  typedef int SOCKET;
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR (-1)
  #define closesocket(s) close(s)
#endif

namespace pockethttp {

  #ifdef _WIN32
    WinSockManager& WinSockManager::getInstance() {
      static WinSockManager instance;
      return instance;
    }

    bool WinSockManager::isInitialized() const {
      return initialized_;
    }

    WinSockManager::WinSockManager() {
      WSADATA wsaData;
      if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0) {
        initialized_ = true;
        pockethttp_log("[WinSockManager] WinSock initialized successfully");
      } else {
        pockethttp_error("[WinSockManager] Failed to initialize WinSock");
      }
    }
    
    WinSockManager::~WinSockManager() {
      if (initialized_) {
        WSACleanup();
        pockethttp_log("[WinSockManager] WinSock cleanup completed");
      }
    }
  #endif // _WIN32

  pockethttp::HttpResult SocketWrapper::openTCPSocket(const std::string& host, int port) {
    pockethttp_log("[SocketWrapper] Attempting to connect to " << host << ":" << port);

    if (connected_ || socket_fd_ != INVALID_SOCKET) {
      pockethttp_log("[SocketWrapper] Socket already connected, disconnecting first");
      disconnect();
    }
    
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    std::string port_str = std::to_string(port);
    int status = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (status != 0) {
      pockethttp_error("[SocketWrapper] Failed to resolve hostname: " << host);
      return pockethttp::HttpResult::HOSTNAME_RESOLUTION_FAILED;
    }

    pockethttp_log("[SocketWrapper] Hostname resolved successfully");
    std::vector<struct addrinfo*> ipv4_addresses;
    std::vector<struct addrinfo*> ipv6_addresses;
    
    for (struct addrinfo* addr_ptr = result; addr_ptr != nullptr; addr_ptr = addr_ptr->ai_next) {
      if (addr_ptr->ai_family == AF_INET) {
        ipv4_addresses.push_back(addr_ptr);
      } else if (addr_ptr->ai_family == AF_INET6) {
        ipv6_addresses.push_back(addr_ptr);
      }
    }

    pockethttp_log(
      "[SocketWrapper] Found " << ipv4_addresses.size() << " IPv4 addresses and " 
      << ipv6_addresses.size() << " IPv6 addresses"
    );

    size_t ipv4_tried = 0;
    size_t ipv6_tried = 0;
    
    while (ipv4_tried < ipv4_addresses.size() || ipv6_tried < ipv6_addresses.size()) {
      std::vector<SOCKET> sockets;
      std::vector<struct addrinfo*> addresses;
        
      for (int i = 0; i < 2 && ipv4_tried < ipv4_addresses.size(); ++i, ++ipv4_tried) {
        addresses.push_back(ipv4_addresses[ipv4_tried]);
      }
        
      if (ipv6_tried < ipv6_addresses.size()) {
        addresses.push_back(ipv6_addresses[ipv6_tried]);
        ipv6_tried++;
      }
        
      while (addresses.size() < 3 && ipv6_tried < ipv6_addresses.size()) {
        addresses.push_back(ipv6_addresses[ipv6_tried]);
        ipv6_tried++;
      }

      pockethttp_log("[SocketWrapper] Attempting parallel connection to " << addresses.size() << " addresses");

      for (auto addr_ptr : addresses) {
        SOCKET sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
        
        if (sock == INVALID_SOCKET) {
          pockethttp_error("[SocketWrapper] Failed to create socket");
          continue;
        }
            
        #ifdef _WIN32
          unsigned long mode = 1;
          ioctlsocket(sock, FIONBIO, &mode);
        #else
          int flags = fcntl(sock, F_GETFL, 0);
          fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        #endif
            
        int connect_result = ::connect(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen);
        if (connect_result == SOCKET_ERROR) {
          #ifdef _WIN32
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
              pockethttp_error("[SocketWrapper] Connect failed with error: " << error);
              closesocket(sock);
              continue;
            }
          #else
            if (errno != EINPROGRESS) {
              pockethttp_error("[SocketWrapper] Connect failed: " << strerror(errno));
              closesocket(sock);
              continue;
            }
          #endif
        }
            
        sockets.push_back(sock);
      }
        
      if (sockets.empty()) {
        pockethttp_error("[SocketWrapper] No sockets created for this batch");
        continue;
      }
        
      fd_set write_fds, error_fds;
      struct timeval timeout;
      timeout.tv_sec = 3;
      timeout.tv_usec = 0;
        
      while (!sockets.empty()) {
        FD_ZERO(&write_fds);
        FD_ZERO(&error_fds);
            
        SOCKET max_fd = 0;
        for (SOCKET sock : sockets) {
          FD_SET(sock, &write_fds);
          FD_SET(sock, &error_fds);
          #ifndef _WIN32
            if (sock > max_fd) max_fd = sock;
          #endif
        }
            
        #ifdef _WIN32
          int select_result = select(0, nullptr, &write_fds, &error_fds, &timeout);
        #else
          int select_result = select(max_fd + 1, nullptr, &write_fds, &error_fds, &timeout);
        #endif
            
        if (select_result == SOCKET_ERROR) {
          pockethttp_error("[SocketWrapper] Select failed during connection");
          break;
        }
        if (select_result == 0) {
          pockethttp_log("[SocketWrapper] Connection timeout");
          break;
        }
            
        for (size_t i = 0; i < sockets.size(); ++i) {
          SOCKET sock = sockets[i];
                
          if (FD_ISSET(sock, &error_fds)) {
            pockethttp_error("[SocketWrapper] Socket error detected");
            closesocket(sock);
            sockets.erase(sockets.begin() + i);
            addresses.erase(addresses.begin() + i);
            --i;
            continue;
          }
                
          if (FD_ISSET(sock, &write_fds)) {
            int error = 0;
            socklen_t error_len = sizeof(error);
                    
            #ifdef _WIN32
              int sockopt = (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &error_len) == 0 && error == 0);
            #else
              int sockopt = (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &error_len) == 0 && error == 0);
            #endif

            if (sockopt) {
              char addr_str[INET6_ADDRSTRLEN];
              void* addr;
              if (addresses[i]->ai_family == AF_INET) {
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)addresses[i]->ai_addr;
                addr = &(ipv4->sin_addr);
              } else {
                struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)addresses[i]->ai_addr;
                addr = &(ipv6->sin6_addr);
              }
                
              inet_ntop(addresses[i]->ai_family, addr, addr_str, INET6_ADDRSTRLEN);
              pockethttp_log("[SocketWrapper] Successfully connected to " << addr_str << ":" << port);

              #ifdef _WIN32
                unsigned long mode = 0;
                ioctlsocket(sock, FIONBIO, &mode);
              #else
                int flags = fcntl(sock, F_GETFL, 0);
                if (flags == -1) {
                    pockethttp_error("[SocketWrapper] fcntl(F_GETFL) failed: " << strerror(errno));
                } else {
                    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
                    int new_flags = fcntl(sock, F_GETFL, 0);
                    pockethttp_log("[SocketWrapper] Socket (" << sock << ") flags after F_SETFL: " << new_flags);
                }
              #endif
                        
              for (size_t j = 0; j < sockets.size(); ++j) {
                if (j != i) closesocket(sockets[j]);
              }
                        
              this->socket_fd_ = sock;
              this->connected_ = true;
              this->last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
                        
              freeaddrinfo(result);
              return pockethttp::HttpResult::SUCCESS;

            } else {
              pockethttp_error("[SocketWrapper] Socket connection failed with error: " << error);
              closesocket(sock);
              sockets.erase(sockets.begin() + i);
              addresses.erase(addresses.begin() + i);
              --i;
            }
          }
        }
      }
        
      for (SOCKET sock : sockets) {
        closesocket(sock);
      }
    }

    pockethttp_error("[SocketWrapper] Failed to connect to " << host << ":" << port);
    freeaddrinfo(result);
    return pockethttp::HttpResult::OPEN_TCP_SOCKET_FAILED;
  }

} // namespace pockethttp


// pockethttp/Sockets/TCPSocket.cpp
// #include "pockethttp/Buffer.hpp"
// #include "pockethttp/Sockets/TCPSocket.hpp"
// #include "pockethttp/Sockets/SocketWrapper.hpp"
// #include "pockethttp/Timestamp.hpp"
// #include "pockethttp/Logs.hpp"
// #include "pockethttp/Results.hpp"

#include <string>
#include <iostream>
#include <cstring>
#include <stdexcept>
#include <chrono>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
    typedef SSIZE_T ssize_t;
#else
    #include <sys/socket.h>
    #include <sys/ioctl.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>  
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    typedef int SOCKET;
    #define INVALID_SOCKET (-1)
    #define SOCKET_ERROR (-1)
    #define closesocket(s) close(s)
#endif

namespace pockethttp {

  TCPSocket::TCPSocket() {
    this->connected_ = false;
    this->socket_fd_ = INVALID_SOCKET;
    
    pockethttp_log("[TCPSocket] TCPSocket constructor called");
    #ifdef _WIN32
      auto& manager = WinSockManager::getInstance();
      if (!manager.isInitialized()) {
        pockethttp_error("[TCPSocket] WinSock not initialized, throwing exception");
        throw std::runtime_error("WinSock initialization failed");
      }
    #endif
  }

  TCPSocket::~TCPSocket() {
    pockethttp_log("[TCPSocket] TCPSocket destructor called");
    this->disconnect();
  }


  pockethttp::HttpResult TCPSocket::connect(const std::string &host, int port) {
    return this->openTCPSocket(host, port);
  }

  void TCPSocket::disconnect() {
    if (this->socket_fd_ != INVALID_SOCKET) {
      pockethttp_log("[TCPSocket] Disconnecting socket");
      closesocket(this->socket_fd_);
      this->socket_fd_ = INVALID_SOCKET;
      this->connected_ = false;
    }
  }


  size_t TCPSocket::send(const unsigned char* buffer, const size_t size) {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_error("[TCPSocket] Cannot send data: socket not connected");
      return pockethttp::Buffer::error;
    }

    pockethttp_log("[TCPSocket] Sending " << size << " bytes");
    size_t total_sent = 0;
    
    while (total_sent < size) {
      ssize_t bytes_sent = ::send(this->socket_fd_, (const char *)(buffer + total_sent), size - total_sent, 0);
      if (bytes_sent == SOCKET_ERROR || bytes_sent < 0) {
        #ifdef _WIN32
          pockethttp_error("[TCPSocket] Send failed with error: " << WSAGetLastError());
        #else
          pockethttp_error("[TCPSocket] Send failed with error: " << strerror(errno));
        #endif
        return pockethttp::Buffer::error;
      }
        
      total_sent += bytes_sent;
      pockethttp_log("[TCPSocket] Sent " << bytes_sent << " bytes. (" << total_sent << "/" << size << ")");
    }
    
    last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
    pockethttp_log("[TCPSocket] Data sent successfully");
    return total_sent;
  }

  size_t TCPSocket::receive(unsigned char* buffer, size_t size, const int64_t& timeout) {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_error("[TCPSocket] Cannot receive data: socket not connected");
      return pockethttp::Buffer::error;
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(this->socket_fd_, &read_fds);

    // Wait a short time period to see if there is data.
    // This avoids blocking indefinitely.
    struct timeval timeout_;
    timeout_.tv_sec = timeout / 1000; // seconds
    timeout_.tv_usec = (timeout % 1000) * 1000; // microseconds

    int select_result = select(this->socket_fd_ + 1, &read_fds, nullptr, nullptr, &timeout_);
    pockethttp_log("[TCPSocket] Select result: " << select_result);

    if (select_result == SOCKET_ERROR) {
      #ifdef _WIN32
        pockethttp_error("[TCPSocket] Select failed with error: " << WSAGetLastError());
      #else
        pockethttp_error("[TCPSocket] Select failed with error: " << strerror(errno));
      #endif

      this->disconnect();
      return pockethttp::Buffer::error;
    }

    if (select_result == 0 || !FD_ISSET(this->socket_fd_, &read_fds)) {
      // No data or timeout, return Buffer error.
      pockethttp_error("[TCPSocket] No data available for reading (timeout [" << timeout << "] or no data): (" << errno << ") " << strerror(errno));
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    ssize_t bytes_received = ::recv(this->socket_fd_, (char *)buffer, size, 0);
    pockethttp_log("[TCPSocket] Received " << bytes_received << " bytes");

    if (bytes_received == SOCKET_ERROR) {
      #ifdef _WIN32
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
          pockethttp_error("[TCPSocket] Receive failed with error: " << err);
          this->disconnect();
        }
      #else
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
          pockethttp_error("[TCPSocket] Receive failed with error: " << strerror(errno));
          this->disconnect();
        }
      #endif
      return pockethttp::Buffer::error;
    }

    if (bytes_received == 0) {
      pockethttp_error("[TCPSocket] Server closed the connection: (" << errno << ") " << strerror(errno));
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
    return bytes_received;
  }


  bool TCPSocket::isConnected() {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_log("[TCPSocket] Socket is not connected");
      return false;
    }
    
    fd_set read_fds, write_fds, error_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    FD_ZERO(&error_fds);
    FD_SET(socket_fd_, &read_fds);
    FD_SET(socket_fd_, &write_fds);
    FD_SET(socket_fd_, &error_fds);
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    int result = select(this->socket_fd_ + 1, &read_fds, &write_fds, &error_fds, &timeout);
    if (result < 0) {
      pockethttp_error("[TCPSocket] Select failed in isConnected check");
      this->connected_ = false;
      this->socket_fd_ = INVALID_SOCKET;
      return false;
    }
    
    if (FD_ISSET(this->socket_fd_, &error_fds)) {
      pockethttp_error("[TCPSocket] Socket error detected in isConnected check");
      this->connected_ = false;
      this->socket_fd_ = INVALID_SOCKET;
      return false;
    }

    if (FD_ISSET(this->socket_fd_, &read_fds)) {
      char test_buffer[1];  
      #ifdef _WIN32
        int peek_result = ::recv(this->socket_fd_, test_buffer, 1, MSG_PEEK);
      #else
        int peek_result = ::recv(this->socket_fd_, test_buffer, 1, MSG_PEEK | MSG_DONTWAIT);
      #endif
        
      if (peek_result == 0) {
        pockethttp_log("[TCPSocket] Connection closed by peer");
        this->connected_ = false;
        this->socket_fd_ = INVALID_SOCKET;
        return false;
      }
        
      if (peek_result == SOCKET_ERROR) {
        #ifdef _WIN32
          int error = WSAGetLastError();
          if (error != WSAEWOULDBLOCK && error != WSAENOTSOCK) {
            pockethttp_error("[TCPSocket] Peek operation failed with error: " << error);
            this->connected_ = false;
            this->socket_fd_ = INVALID_SOCKET;
            return false;
          }
        #else
          if (errno != EAGAIN && errno != EWOULDBLOCK) {
            pockethttp_error("[TCPSocket] Peek operation failed: " << strerror(errno));
            this->connected_ = false;
            this->socket_fd_ = INVALID_SOCKET;
            return false;
          }
        #endif
      }
    }
    
    pockethttp_log("[TCPSocket] Socket connection is healthy");
    return true;
  }

  int64_t TCPSocket::getTimestamp() const {
    return this->last_used_timestamp_;
  }

} // namespace pockethttp

// pockethttp/Sockets/TLSSocket.cpp
// #include "pockethttp/Sockets/TLSSocket.hpp"
// #include "pockethttp/Logs.hpp"
// #include "pockethttp/Timestamp.hpp"
// #include "pockethttp/Buffer.hpp"
// #include "pockethttp/SystemCerts.hpp"
// #include "pockethttp/Results.hpp"

#ifdef USE_POCKET_HTTP_BEARSSL


#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <stdio.h>

#if __has_include("bearssl.h")
  #include <bearssl.h>
#elif __has_include("bearssl/bearssl.h")
  #include <bearssl/bearssl.h>
#else
  #error "Cannot find bearssl.h or bearssl/bearssl.h"
#endif

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef int socklen_t;
  typedef SSIZE_T ssize_t;
#else
  #include <arpa/inet.h>
  #include <errno.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <sys/socket.h>
  #include <unistd.h>
  typedef int SOCKET;
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR (-1)
  #define closesocket(s) close(s)
#endif

namespace pockethttp {

  // Private/protected methods

  int TLSSocket::sock_read(void* ctx, unsigned char* buf, size_t len) {
    SOCKET* socket_fd = static_cast<SOCKET*>(ctx);

    for (;;) {
      #ifdef _WIN32
        int rlen = recv(*socket_fd, reinterpret_cast<char*>(buf), len, 0);
      #else
        ssize_t rlen = read(*socket_fd, buf, len);
      #endif
        
      if (rlen <= 0) {
        #ifdef _WIN32
          int error = WSAGetLastError();
          if (error == WSAEINTR) continue;
        #else
          if (rlen < 0 && errno == EINTR) continue;
        #endif
        return -1;
      }
      return static_cast<int>(rlen);
    }
  }

  int TLSSocket::sock_write(void* ctx, const unsigned char* buf, size_t len) {
    SOCKET* socket_fd = static_cast<SOCKET*>(ctx);
    
    for (;;) {
      #ifdef _WIN32
        int wlen = ::send(*socket_fd, reinterpret_cast<const char*>(buf), len, 0);
      #else
        ssize_t wlen = write(*socket_fd, buf, len);
      #endif
        
      if (wlen <= 0) {
        #ifdef _WIN32
          int error = WSAGetLastError();
          if (error == WSAEINTR) continue;
        #else
          if (wlen < 0 && errno == EINTR) continue;
        #endif
        return -1;
      }
      return static_cast<int>(wlen);
    }
  }


  bool TLSSocket::loadCerts() {
    this->trust_anchors_ = pockethttp::SystemCerts::getBearSSLTrustAnchors();
    this->trust_anchors_count_ = pockethttp::SystemCerts::getBearSSLTrustAnchorsSize();
    return true;
  }

  pockethttp::HttpResult TLSSocket::initializeTLS(const std::string& hostname) {
    pockethttp_log("[TLSSocket] Initializing TLS for hostname: " << hostname);
    
    try {
      // Allocate contexts using malloc instead of new
      this->ssl_client_ = static_cast<br_ssl_client_context*>(malloc(sizeof(br_ssl_client_context)));
      this->x509_context_ = static_cast<br_x509_minimal_context*>(malloc(sizeof(br_x509_minimal_context)));
      this->sslio_context_ = static_cast<br_sslio_context*>(malloc(sizeof(br_sslio_context)));
        
      if (!this->ssl_client_ || !this->x509_context_ || !this->sslio_context_) {
        return pockethttp::HttpResult::FAILED_TO_ALLOCATE_TLS_CONTEXT;
      }
        
      // Allocate I/O buffer
      this->iobuf_ = static_cast<unsigned char*>(malloc(BR_SSL_BUFSIZE_BIDI));
      if (!iobuf_) {
        return pockethttp::HttpResult::FAILED_TO_ALLOCATE_IO_BUFFER;
      }

      // Load certs
      if (!this->loadCerts()) {
        return pockethttp::HttpResult::FAILED_TO_LOAD_CERTIFICATES;
      }
        
      // Initialize the client context with full profile and X.509 validation
      br_ssl_client_init_full(this->ssl_client_, this->x509_context_, this->trust_anchors_, this->trust_anchors_count_);

      // Set the I/O buffer
      br_ssl_engine_set_buffer(&this->ssl_client_->eng, this->iobuf_, BR_SSL_BUFSIZE_BIDI, 1);
        
      // Reset the client context for new handshake
      br_ssl_client_reset(this->ssl_client_, hostname.c_str(), 0);
        
      // Initialize the simplified I/O wrapper context
      br_sslio_init(this->sslio_context_, &this->ssl_client_->eng, this->sock_read, &this->socket_fd_, this->sock_write, &this->socket_fd_);

      pockethttp_log("[TLSSocket] TLS initialization successful");
      return pockethttp::HttpResult::SUCCESS;
    } catch (const std::exception& e) {
      pockethttp_error("[TLSSocket] TLS initialization failed: " << e.what());
      return pockethttp::HttpResult::FAILED_TO_INIT_TLS;
    }
  }

  pockethttp::HttpResult TLSSocket::performTLSHandshake(const std::string& hostname) {
    pockethttp_log("[TLSSocket] Starting TLS handshake for hostname: " << hostname);
    
    // Force handshake by attempting to flush
    if (br_sslio_flush(this->sslio_context_) < 0) {
      int ssl_err = br_ssl_engine_last_error(&this->ssl_client_->eng);
      pockethttp_error("[TLSSocket] TLS handshake failed during flush: " << ssl_err << " for hostname: " << hostname);

      if (ssl_err == BR_ERR_X509_NOT_TRUSTED) return pockethttp::HttpResult::INVALID_CERTIFICATE;
      else return pockethttp::HttpResult::TLS_FLUSH_ERROR;
    }
    
    // Check final state
    unsigned state = br_ssl_engine_current_state(&this->ssl_client_->eng);
    if (state == BR_SSL_CLOSED) {
      int err = br_ssl_engine_last_error(&this->ssl_client_->eng);
      if (err != 0) {
        pockethttp_error("[TLSSocket] TLS handshake failed with SSL error: " << err);
        return pockethttp::HttpResult::UNKNOWN_ERROR;
      }
    }

    pockethttp_log("[TLSSocket] TLS handshake completed successfully");
    return pockethttp::HttpResult::SUCCESS;
  }

  void TLSSocket::cleanupTLS() {
    pockethttp_log("[TLSSocket] Cleaning up TLS resources");
    
    if (this->sslio_context_) {
      free(this->sslio_context_);
      this->sslio_context_ = nullptr;
    }
    
    if (this->ssl_client_) {
      free(this->ssl_client_);
      this->ssl_client_ = nullptr;
    }
    
    if (this->x509_context_) {
      free(this->x509_context_);
      this->x509_context_ = nullptr;
    }
    
    if (this->iobuf_) {
      free(this->iobuf_);
      this->iobuf_ = nullptr;
    }
  }

  // Public methods

  TLSSocket::TLSSocket() 
    : ssl_client_(nullptr),
      x509_context_(nullptr),
      sslio_context_(nullptr),
      iobuf_(nullptr) {
    pockethttp_log("[TLSSocket] TLSSocket constructor called");

    this->connected_ = false;
    this->socket_fd_ = INVALID_SOCKET;
    this->last_used_timestamp_ = 0;
    
    #ifdef _WIN32
      auto& manager = WinSockManager::getInstance();
      if (!manager.isInitialized()) {
        pockethttp_log("[TLSSocket] WinSock not initialized, throwing exception");
        throw std::runtime_error("WinSock initialization failed");
      }
    #endif
  }

  TLSSocket::~TLSSocket() {
    pockethttp_log("[TLSSocket] TLSSocket destructor called");
    this->disconnect();
  }

  pockethttp::HttpResult TLSSocket::connect(const std::string& host, int port) {
    pockethttp_log("[TLSSocket] Attempting to connect to " << host << ":" << port);

    if (this->connected_ || this->socket_fd_ != INVALID_SOCKET) {
      pockethttp_log("[TLSSocket] Socket already connected, disconnecting first.");
      this->disconnect();
    }

    // Create TCP connection
    pockethttp::HttpResult open_state = this->openTCPSocket(host, port);
    if (open_state != pockethttp::HttpResult::SUCCESS || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_error("[TLSSocket] Failed to create TCP connection.");
      this->disconnect();
      if (open_state != pockethttp::HttpResult::SUCCESS) return open_state;
      else return pockethttp::HttpResult::OPEN_TCP_SOCKET_FAILED;
    }

    // Initialize TLS
    open_state = this->initializeTLS(host);
    if (open_state != pockethttp::HttpResult::SUCCESS) {
      pockethttp_error("[TLSSocket] Failed to initialize TLS.");
      this->disconnect();
      return open_state;
    }

    // Perform TLS handshake
    open_state = this->performTLSHandshake(host);
    if (open_state != pockethttp::HttpResult::SUCCESS) {
      pockethttp_error("[TLSSocket] TLS handshake failed.");
      this->disconnect();
      return open_state;
    }

    this->connected_ = true;
    this->last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();

    pockethttp_log("[TLSSocket] Successfully connected to " << host << ":" << port);
    return pockethttp::HttpResult::SUCCESS;
  }

  void TLSSocket::disconnect() {
    if (this->socket_fd_ != INVALID_SOCKET) {
      pockethttp_log("[TLSSocket] Disconnecting socket");
        
      // Properly close SSL connection if connected
      if (this->connected_ && this->sslio_context_) {
        // Try to send close_notify alert
        br_sslio_close(this->sslio_context_);
      }

      this->cleanupTLS();
      closesocket(this->socket_fd_);
      this->socket_fd_ = INVALID_SOCKET;
      this->connected_ = false;
    }
}

  size_t TLSSocket::send(const unsigned char* buffer, const size_t size) {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET || !this->sslio_context_) {
      pockethttp_error("[TLSSocket] Cannot send data: socket not connected or SSL context invalid.");
      return pockethttp::Buffer::error;
    }

    pockethttp_log("[TLSSocket] Sending " << size << " bytes.");
    
    // Send data using br_sslio_write_all for complete transmission
    int result = br_sslio_write_all(this->sslio_context_, buffer, size);
    if (result < 0) {
      pockethttp_error("[TLSSocket] SSL write failed.");
      return pockethttp::Buffer::error;
    }
    
    // Flush the SSL buffer
    if (br_sslio_flush(this->sslio_context_) < 0) {
      pockethttp_error("[TLSSocket] SSL flush failed after write.");
      return pockethttp::Buffer::error;
    }
    
    this->last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
    pockethttp_log("[TLSSocket] Data sent successfully.");
    return size;
  }

  size_t TLSSocket::receive(unsigned char* buffer, size_t size, const int64_t& timeout) {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET || !this->sslio_context_) {
      pockethttp_error("[TLSSocket] Cannot receive data: socket not connected or invalid sslio context.");
      return pockethttp::Buffer::error;
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(this->socket_fd_, &read_fds);

    // Wait a short time period to see if there is data.
    // This avoids blocking indefinitely.
    struct timeval timeout_;
    timeout_.tv_sec = timeout / 1000; // seconds
    timeout_.tv_usec = (timeout % 1000) * 1000; // microseconds

    if (this->socket_fd_ == INVALID_SOCKET || this->socket_fd_ < 0) {
      pockethttp_error("[TLSSocket] Select called with invalid socket: " << this->socket_fd_);
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    #ifndef _WIN32
      int flags = fcntl(this->socket_fd_, F_GETFL, 0);
      int status = fcntl(this->socket_fd_, F_GETFD);
      pockethttp_log("[TLSSocket] Socket FD status: " << status << " (" << errno << ") " << strerror(errno) << ", flags: " << flags);
    #endif

    pockethttp_log("[TLSSocket] Waiting for data with timeout: " << timeout << " ms on descriptor: " << this->socket_fd_);
    int select_result = select(this->socket_fd_ + 1, &read_fds, nullptr, nullptr, &timeout_);
    pockethttp_log("[TLSSocket] Select result: " << select_result << " with descriptor: " << this->socket_fd_);

    if (select_result == SOCKET_ERROR) {
      #ifdef _WIN32
        pockethttp_error("[TLSSocket] Select failed with error: " << WSAGetLastError());
      #else
        pockethttp_error("[TLSSocket] Select failed with error: " << strerror(errno));
      #endif

      this->disconnect();
      return pockethttp::Buffer::error;
    }

    if (select_result == 0 || !FD_ISSET(this->socket_fd_, &read_fds)) {
      // No data or timeout, return Buffer error.
      pockethttp_error("[TLSSocket] No data available for reading (timeout [" << timeout << "] or no data): (" << errno << ") " << strerror(errno));
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    ssize_t bytes_received = br_sslio_read(this->sslio_context_, buffer, size);
    if (bytes_received < 0) {
      // Check if it's a SSL error or just no data available
      unsigned state = br_ssl_engine_current_state(&this->ssl_client_->eng);
      if (state == BR_SSL_CLOSED) {
        int err = br_ssl_engine_last_error(&this->ssl_client_->eng);
        if (err != 0) {
          pockethttp_error("[TLSSocket] SSL error during receive: " << err);
          this->disconnect();
        } else {
          pockethttp_log("[TLSSocket] SSL connection closed cleanly");
          this->disconnect();
        }
      }

      return pockethttp::Buffer::error;
    }
    
    if (bytes_received == 0) {
      // No data available or connection closed
      pockethttp_log("[TLSSocket] No data received, connection may be closed.");
      return pockethttp::Buffer::error;
    }

    pockethttp_log("[TLSSocket] Received " << bytes_received << " bytes.");
    last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();

    return bytes_received;
  }

  bool TLSSocket::isConnected() {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET || !this->sslio_context_) {
      pockethttp_log("[TLSSocket] Socket is not connected or SSL context is invalid");
      return false;
    }
    
    // Check SSL engine state
    unsigned state = br_ssl_engine_current_state(&this->ssl_client_->eng);
    
    if (state == BR_SSL_CLOSED) {
      int err = br_ssl_engine_last_error(&this->ssl_client_->eng);
      if (err != 0) {
        pockethttp_error("[TLSSocket] SSL engine is closed with error: " << err);
        this->disconnect();
        return false;
      }
    }
    
    // Check underlying TCP connection
    fd_set read_fds, error_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&error_fds);
    FD_SET(this->socket_fd_, &read_fds);
    FD_SET(this->socket_fd_, &error_fds);
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    
    int result = select(this->socket_fd_ + 1, &read_fds, nullptr, &error_fds, &timeout);
    if (result < 0) {
      pockethttp_error("[TLSSocket] Select failed in isConnected check");
      this->disconnect();
      return false;
    }
    
    if (FD_ISSET(this->socket_fd_, &error_fds)) {
      pockethttp_error("[TLSSocket] Socket error detected in isConnected check");
      this->disconnect();
      return false;
    }
    
    pockethttp_log("[TLSSocket] TLS socket connection is healthy");
    return true;
  }
  
  int64_t TLSSocket::getTimestamp() const {
    return this->last_used_timestamp_;
  }

} // namespace pockethttp

#endif // USE_POCKET_HTTP_BEARSSL

// pockethttp/Sockets/MbedTLSSocket.cpp
// #include "pockethttp/Sockets/MbedTLSSocket.hpp"
// #include "pockethttp/Sockets/certs.hpp"
// #include "pockethttp/Logs.hpp"
// #include "pockethttp/Timestamp.hpp"
// #include "pockethttp/Buffer.hpp"
// #include "pockethttp/SystemCerts.hpp"
// #include "pockethttp/Results.hpp"

#ifdef USE_POCKET_HTTP_MBEDTLS


#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <stdio.h>

#if __has_include("mbedtls/ssl.h")
  extern "C" {
    #include <mbedtls/ssl.h>
    #include <mbedtls/x509_crt.h>
    #include <mbedtls/net_sockets.h>
    #include <mbedtls/error.h>
    #include <psa/crypto.h>
  }
#elif __has_include("mbedtls/mbedtls/ssl.h")
  extern "C" {
    #include <mbedtls/mbedtls/ssl.h>
    #include <mbedtls/mbedtls/x509_crt.h>
    #include <mbedtls/mbedtls/net_sockets.h>
    #include <mbedtls/mbedtls/error.h>
    #include <psa/crypto.h>
  }
#else
  #error "Cannot find mbedtls"
#endif

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef int socklen_t;
  typedef SSIZE_T ssize_t;
#else
  #include <arpa/inet.h>
  #include <errno.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <sys/socket.h>
  #include <unistd.h>
  typedef int SOCKET;
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR (-1)
  #define closesocket(s) close(s)
#endif

namespace pockethttp {

  // Private/protected methods
  
  int MbedTLSSocket::psa_rng_wrapper(void * /*p_rng*/, unsigned char *buf, size_t len) {
    // psa_generate_random returns psa_status_t
    return psa_generate_random(buf, len) == PSA_SUCCESS ? 0 : -1;
  }

  bool MbedTLSSocket::loadCerts() {
    #ifdef USE_POCKET_HTTP_MOZILLA_ROOT_CERTS
      for (const std::vector<unsigned char>& derCert : pockethttp::MozillaCA::derCAs) {
        if (derCert.empty()) continue;

        const unsigned char *buf = derCert.data();
        size_t buf_len = derCert.size();

        int ret = mbedtls_x509_crt_parse_der(&this->cacert, buf, buf_len);
        if (ret != 0) {
          pockethttp_error("[MbedTLSSocket] Failed to parse DER certificate, mbedtls_x509_crt_parse_der returned: " << ret << ". skipping");
          continue;
        }
      }
    #endif // USE_POCKET_HTTP_MOZILLA_ROOT_CERTS

    auto der_list = pockethttp::SystemCerts::loadSystemCerts();
    for (const auto& derCert : der_list) {
      if (derCert.empty()) continue;

      const unsigned char *buf = derCert.data();
      size_t buf_len = derCert.size();

      int ret = mbedtls_x509_crt_parse_der(&this->cacert, buf, buf_len);
      if (ret != 0) {
        pockethttp_error("[MbedTLSSocket] Failed to parse DER certificate, mbedtls_x509_crt_parse_der returned: " << ret << ". skipping");
        continue;
      }
    }

    return true;
  }

  pockethttp::HttpResult MbedTLSSocket::initializeTLS(const std::string& hostname) {
    pockethttp_log("[MbedTLSSocket] Initializing TLS for hostname: " << hostname);
    int ret_code = 0;
    
    try {
      // Initialize MbedTLS structures
      mbedtls_ssl_init(&this->ssl);
      mbedtls_ssl_config_init(&this->conf);
      mbedtls_x509_crt_init(&this->cacert);
      mbedtls_net_init(&this->net_ctx);
      this->net_ctx.fd = this->socket_fd_;

      // Initialize PSA Crypto
      if (psa_crypto_init() != PSA_SUCCESS) {
        this->disconnect();
        return pockethttp::HttpResult::FAILED_TO_INIT_TLS;
      }

      // Load certs
      if (!this->loadCerts()) {
        return pockethttp::HttpResult::FAILED_TO_LOAD_CERTIFICATES;
      }
        
      // Configure SSL/TLS settings
      ret_code = mbedtls_ssl_config_defaults(
        &this->conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
      );

      if (ret_code != 0) {
        this->disconnect();
        return pockethttp::HttpResult::FAILED_TO_INIT_TLS;
      }

      // Certificate verification required
      mbedtls_ssl_conf_authmode(&this->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
      mbedtls_ssl_conf_ca_chain(&this->conf, &this->cacert, nullptr);
      // mbedtls_ssl_conf_set_rng(&this->conf, this->psa_rng_wrapper, nullptr);

      ret_code = mbedtls_ssl_setup(&this->ssl, &this->conf);
      if (ret_code != 0) {
        this->disconnect();
        return pockethttp::HttpResult::FAILED_TO_INIT_TLS;
      }

      ret_code = mbedtls_ssl_set_hostname(&this->ssl, hostname.c_str()); /* SNI and verification */
      if (ret_code != 0) {
        this->disconnect();
        return pockethttp::HttpResult::FAILED_TO_INIT_TLS;
      }

      mbedtls_ssl_set_bio(&this->ssl, &this->net_ctx, mbedtls_net_send, mbedtls_net_recv, nullptr);
      pockethttp_log("[MbedTLSSocket] TLS initialization successful");
      return pockethttp::HttpResult::SUCCESS;

    } catch (const std::exception& e) {
      pockethttp_error("[MbedTLSSocket] TLS initialization failed: " << e.what());
      return pockethttp::HttpResult::FAILED_TO_INIT_TLS;
    }
  }

  pockethttp::HttpResult MbedTLSSocket::performTLSHandshake(const std::string& hostname) {
    pockethttp_log("[MbedTLSSocket] Starting TLS handshake for hostname: " << hostname);
    
    // Perform TLS handshake
    int ret_code = 0;
    while ((ret_code = mbedtls_ssl_handshake(&this->ssl)) != 0) {
      if (ret_code == MBEDTLS_ERR_SSL_WANT_READ || ret_code == MBEDTLS_ERR_SSL_WANT_WRITE) {
        continue;
      }

      char errbuf[256];
      mbedtls_strerror(ret_code, errbuf, sizeof(errbuf));
      pockethttp_error("[MbedTLSSocket] TLS handshake error: " << errbuf << " (" << ret_code << ")");
      this->disconnect();
      return pockethttp::HttpResult::FAILED_TO_INIT_TLS;
    }

    uint32_t vrfy_flags = mbedtls_ssl_get_verify_result(&this->ssl);
    if (vrfy_flags != 0) {
      this->disconnect();
      return pockethttp::HttpResult::FAILED_TO_INIT_TLS;
    }

    pockethttp_log("[MbedTLSSocket] TLS handshake completed successfully");
    return pockethttp::HttpResult::SUCCESS;
  }

  void MbedTLSSocket::cleanupTLS() {
    pockethttp_log("[MbedTLSSocket] Cleaning up TLS resources");
    int ret_code = mbedtls_ssl_close_notify(&this->ssl);
    if (ret_code == MBEDTLS_ERR_SSL_WANT_READ || ret_code == MBEDTLS_ERR_SSL_WANT_WRITE) {
      // Try to close again
      int tmp = mbedtls_ssl_close_notify(&this->ssl);
      if (tmp != 0) {
        pockethttp_error("[MbedTLSSocket] Error during SSL close notify: " << tmp << ", original error: " << ret_code << ". Freeing resources anyway.");
      }
    }
    
    mbedtls_x509_crt_free(&this->cacert);
    mbedtls_ssl_free(&this->ssl);
    mbedtls_ssl_config_free(&this->conf);
    mbedtls_net_free(&this->net_ctx);
  }

  // Public methods

  MbedTLSSocket::MbedTLSSocket() {
    pockethttp_log("[MbedTLSSocket] MbedTLSSocket constructor called");

    this->connected_ = false;
    this->socket_fd_ = INVALID_SOCKET;
    this->last_used_timestamp_ = 0;
    
    #ifdef _WIN32
      auto& manager = WinSockManager::getInstance();
      if (!manager.isInitialized()) {
        pockethttp_log("[MbedTLSSocket] WinSock not initialized, throwing exception");
        throw std::runtime_error("WinSock initialization failed");
      }
    #endif
  }

  MbedTLSSocket::~MbedTLSSocket() {
    pockethttp_log("[MbedTLSSocket] MbedTLSSocket destructor called");
    this->disconnect();
  }

  pockethttp::HttpResult MbedTLSSocket::connect(const std::string& host, int port) {
    pockethttp_log("[MbedTLSSocket] Attempting to connect to " << host << ":" << port);

    if (this->connected_ || this->socket_fd_ != INVALID_SOCKET) {
      pockethttp_log("[MbedTLSSocket] Socket already connected, disconnecting first.");
      this->disconnect();
    }

    // Create TCP connection
    pockethttp::HttpResult open_state = this->openTCPSocket(host, port);
    if (open_state != pockethttp::HttpResult::SUCCESS || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_error("[MbedTLSSocket] Failed to create TCP connection.");
      this->disconnect();
      if (open_state != pockethttp::HttpResult::SUCCESS) return open_state;
      else return pockethttp::HttpResult::OPEN_TCP_SOCKET_FAILED;
    }

    // Initialize TLS
    open_state = this->initializeTLS(host);
    if (open_state != pockethttp::HttpResult::SUCCESS) {
      pockethttp_error("[MbedTLSSocket] Failed to initialize TLS.");
      this->disconnect();
      return open_state;
    }

    // Perform TLS handshake
    open_state = this->performTLSHandshake(host);
    if (open_state != pockethttp::HttpResult::SUCCESS) {
      pockethttp_error("[MbedTLSSocket] TLS handshake failed.");
      this->disconnect();
      return open_state;
    }

    this->connected_ = true;
    this->last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();

    pockethttp_log("[MbedTLSSocket] Successfully connected to " << host << ":" << port);
    return pockethttp::HttpResult::SUCCESS;
  }

  void MbedTLSSocket::disconnect() {
    if (this->socket_fd_ != INVALID_SOCKET) {
      pockethttp_log("[MbedTLSSocket] Disconnecting socket");

      this->cleanupTLS();
      closesocket(this->socket_fd_);
      this->socket_fd_ = INVALID_SOCKET;
      this->connected_ = false;
    }
}

  size_t MbedTLSSocket::send(const unsigned char* buffer, const size_t size) {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_error("[MbedTLSSocket] Cannot send data: socket not connected or SSL is invalid.");
      return pockethttp::Buffer::error;
    }

    pockethttp_log("[MbedTLSSocket] Sending " << size << " bytes.");

    // Send data using br_sslio_write_all for complete transmission
    int result = mbedtls_ssl_write(&this->ssl, buffer, size);
    if (result < 0 && result != MBEDTLS_ERR_SSL_WANT_READ && result != MBEDTLS_ERR_SSL_WANT_WRITE) {
      pockethttp_error("[MbedTLSSocket] SSL write failed.");
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    this->last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
    pockethttp_log("[MbedTLSSocket] Data sent successfully.");
    return size;
  }

  size_t MbedTLSSocket::receive(unsigned char* buffer, size_t size, const int64_t& timeout) {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_error("[MbedTLSSocket] Cannot receive data: socket not connected or invalid SSL context.");
      return pockethttp::Buffer::error;
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(this->socket_fd_, &read_fds);

    // Wait a short time period to see if there is data.
    // This avoids blocking indefinitely.
    struct timeval timeout_;
    timeout_.tv_sec = timeout / 1000; // seconds
    timeout_.tv_usec = (timeout % 1000) * 1000; // microseconds

    if (this->socket_fd_ == INVALID_SOCKET || this->socket_fd_ < 0) {
      pockethttp_error("[MbedTLSSocket] Select called with invalid socket: " << this->socket_fd_);
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    #ifndef _WIN32
      int flags = fcntl(this->socket_fd_, F_GETFL, 0);
      int status = fcntl(this->socket_fd_, F_GETFD);
      pockethttp_log("[MbedTLSSocket] Socket FD status: " << status << " (" << errno << ") " << strerror(errno) << ", flags: " << flags);
    #endif

    pockethttp_log("[MbedTLSSocket] Waiting for data with timeout: " << timeout << " ms on descriptor: " << this->socket_fd_);
    int select_result = select(this->socket_fd_ + 1, &read_fds, nullptr, nullptr, &timeout_);
    pockethttp_log("[MbedTLSSocket] Select result: " << select_result << " with descriptor: " << this->socket_fd_);

    if (select_result == SOCKET_ERROR) {
      #ifdef _WIN32
        pockethttp_error("[MbedTLSSocket] Select failed with error: " << WSAGetLastError());
      #else
        pockethttp_error("[MbedTLSSocket] Select failed with error: " << strerror(errno));
      #endif

      this->disconnect();
      return pockethttp::Buffer::error;
    }

    if (select_result == 0 || !FD_ISSET(this->socket_fd_, &read_fds)) {
      // No data or timeout, return Buffer error.
      pockethttp_error("[MbedTLSSocket] No data available for reading (timeout [" << timeout << "] or no data): (" << errno << ") " << strerror(errno));
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    ssize_t bytes_received = mbedtls_ssl_read(&this->ssl, buffer, size);
    if (bytes_received == MBEDTLS_ERR_SSL_WANT_READ || bytes_received == MBEDTLS_ERR_SSL_WANT_WRITE) {
      // No data available right now
      pockethttp_log("[MbedTLSSocket] No data available for reading right now (WANT_READ/WRITE).");
      return 0;
    }

    if (bytes_received == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
      pockethttp_log("[MbedTLSSocket] Received new session ticket.");
      return 0;
    }

    if (bytes_received == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
      pockethttp_log("[MbedTLSSocket] SSL connection closed by peer");
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    if (bytes_received == 0) {
      pockethttp_log("[MbedTLSSocket] No data received, connection may be closed.");
      this->disconnect();
      return pockethttp::Buffer::error;
    }
    
    if (bytes_received < 0) {
      char errbuf[256];
      mbedtls_strerror(bytes_received, errbuf, sizeof(errbuf));
      pockethttp_error("[MbedTLSSocket] SSL read error: " << errbuf << " (" << bytes_received << ")");
      this->disconnect();
      return 0;
    }

    pockethttp_log("[MbedTLSSocket] Received " << bytes_received << " bytes.");
    last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();

    return bytes_received;
  }

  bool MbedTLSSocket::isConnected() {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_log("[MbedTLSSocket] Socket is not connected");
      return false;
    }
    
    // Check underlying TCP connection
    fd_set read_fds, error_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&error_fds);
    FD_SET(this->socket_fd_, &read_fds);
    FD_SET(this->socket_fd_, &error_fds);
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    
    int result = select(this->socket_fd_ + 1, &read_fds, nullptr, &error_fds, &timeout);
    if (result < 0) {
      pockethttp_error("[MbedTLSSocket] Select failed in isConnected check");
      this->disconnect();
      return false;
    }
    
    if (FD_ISSET(this->socket_fd_, &error_fds)) {
      pockethttp_error("[MbedTLSSocket] Socket error detected in isConnected check");
      this->disconnect();
      return false;
    }

    pockethttp_log("[MbedTLSSocket] TLS socket connection is healthy");
    return true;
  }
  
  int64_t MbedTLSSocket::getTimestamp() const {
    return this->last_used_timestamp_;
  }

} // namespace pockethttp

#endif // USE_POCKET_HTTP_MBEDTLS

// pockethttp/Sockets/SocketPool.cpp
// #include "pockethttp/Sockets/SocketPool.hpp"
// #include "pockethttp/Sockets/TCPSocket.hpp"
// #include "pockethttp/Results.hpp"

#if defined(USE_POCKET_HTTP_MBEDTLS)
// #include "pockethttp/Sockets/MbedTLSSocket.hpp"
#elif defined(USE_POCKET_HTTP_BEARSSL)
// #include "pockethttp/Sockets/TLSSocket.hpp"
#endif


#include <map>
#include <memory>
#include <string>
#include <vector>

namespace pockethttp {

  int SocketPool::last_result = pockethttp::HttpResult::SUCCESS;

  std::map<std::string, std::vector<std::shared_ptr<pockethttp::SocketWrapper>>> SocketPool::pool_;
  
  std::map<std::string, pockethttp::SocketCreator> SocketPool::protocols_ = {
    {"http", []() { return std::make_shared<pockethttp::TCPSocket>(); }},
    #if defined(USE_POCKET_HTTP_MBEDTLS)
      {"https", []() { return std::make_shared<pockethttp::MbedTLSSocket>(); }},
    #elif defined(USE_POCKET_HTTP_BEARSSL)
      {"https", []() { return std::make_shared<pockethttp::TLSSocket>(); }},
    #endif
  };

} // namespace pockethttp


// pockethttp/Http.cpp
#define NOMINMAX
#include <algorithm>
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

// #include "pockethttp/Logs.hpp"
// #include "pockethttp/Random.hpp"
// #include "pockethttp/Sockets/SocketPool.hpp"
// #include "pockethttp/Http.hpp"
// #include "pockethttp/Buffer.hpp"
// #include "pockethttp/Decompress.hpp"
// #include "pockethttp/Request.hpp"
#include <cstring>
#include <cctype>

#define POCKET_HTTP_MAX_ATTEMPTS 10
#define POCKET_HTTP_CHUNK_SIZE 16384 // 16kb
#define BOUNDARY_PREFIX "------------------PHTTP"

namespace pockethttp {

  Http::Http() : timeout_(30000) {}
  Http::Http(int64_t timeout) : timeout_(timeout) {}
  Http::~Http() {}

  pockethttp::HttpResult Http::request(pockethttp::Request& req, pockethttp::Response& res) {
    pockethttp::Remote remote = pockethttp::utils::parseUrl(req.url);

    if (!req.headers.has("Content-Length")) {
      if (req.body_callback == nullptr && !req.body.empty()) {
        req.headers.set("Content-Length", std::to_string(req.body.size()));
      } else if (req.body_callback != nullptr && req.body.empty()) {
        req.headers.set("Transfer-Encoding", "chunked");
      }
    }

    RequestCallback body_callback = [&req](unsigned char* data, size_t* read_data, const size_t max_size, const size_t total_read) -> bool {  
      if (req.body_callback == nullptr) {
        if (req.body.empty()) {
          pockethttp_log("[Http] No body to send");
          *read_data = 0; // No body to read
          return false; // No more data to read
        } else {
          size_t to_read = std::min(max_size, req.body.size() - total_read);
          if (to_read > 0) {
            std::memcpy(data, req.body.data() + total_read, to_read);
            *read_data = to_read;
            return true; // More data to read
          } else {
            *read_data = 0; // No more data to read
            return false; // No more data to read
          }
        }
      } else {
        // Custom body callback
        return req.body_callback(data, read_data, max_size, total_read);
      }
    };

    unsigned short redirect_count = 0;
    return request(remote, req.method, req.headers, res, body_callback, redirect_count, req.max_redirects, req.follow_redirects);
  }

  pockethttp::HttpResult Http::request(pockethttp::FormDataRequest& req, pockethttp::Response& res) {
    pockethttp::Remote remote = pockethttp::utils::parseUrl(req.url);
    std::string boundary = this->generateBoundary();
    size_t total_length = 2 + boundary.size() + 4; // For the final boundary and CRLF

    req.headers.set("Content-Type", "multipart/form-data; boundary=" + boundary);
    if (req.headers.has("Content-Length")) {
      req.headers.remove("Content-Length");
      pockethttp_log("[Http] Removed Content-Length header for FormDataRequest");
    }

    bool useTransferChunked = false;
    for (auto item : req.form_data) {
      if (item.value_callback != nullptr) {
        if (item.content_length == pockethttp::Buffer::error) {
          useTransferChunked = true;
          break;
        }

        if (item.filename.empty()) {
          pockethttp_error("FormDataItem with value_callback must have filename set");
          return pockethttp::HttpResult::FORMDATA_FILENAME_MISSING;
        }

        if (item.content_type.empty()) {
          pockethttp_error("FormDataItem with value_callback must have content_type set");
          return pockethttp::HttpResult::FORMDATA_CONTENT_TYPE_MISSING;
        }

        // file
        total_length += 2 + boundary.size() + 2 
                      + 38 + item.name.size() + 13 + item.filename.size() + 3 // Content-Disposition: form-data; name="<name>"; filename="<filename>"\r\n
                      + 14 + item.content_type.size() + 2                     // Content-Type: <content_type>\r\n
                      + 2                                                     // \r\n
                      + item.content_length + 2;                              // <data>\r\n
      } else {
        // field
        total_length += 2 + boundary.size() + 2 
                      + 38 + item.name.size() + 3 // Content-Disposition: form-data; name="<name>"\r\n
                      + 2                         // \r\n
                      + item.value.size() + 2;    // <data>\r\n
      }
    }

    if (!useTransferChunked && total_length > 0) {
      req.headers.set("Content-Length", std::to_string(total_length));
    } else {
      useTransferChunked = true;
      req.headers.set("Transfer-Encoding", "chunked");
    }

    std::vector<FormDataItem>::iterator it = req.form_data.begin();
    pockethttp::FormDataItemState form_data_state;
    form_data_state.item = it;

    RequestCallback body_callback = [&req, &boundary, &useTransferChunked, &form_data_state](unsigned char* data, size_t* read_data, const size_t max_size, const size_t total_read) -> bool {
      
      switch (form_data_state.state) {
        case pockethttp::FormDataItemStateEnum::FORMDATA_HEADER: {
          pockethttp_log("[Http] Sending form-data header for item: " << form_data_state.item->name);
          // Create header if not created yet
          if (form_data_state.header == "") {
            form_data_state.header += "--" + boundary + "\r\n"
              + "Content-Disposition: form-data; name=\"" + form_data_state.item->name + "\"";

            if (form_data_state.item->value_callback != nullptr) { // file

              form_data_state.header += "; filename=\"" + form_data_state.item->filename + "\"\r\n"
                + "Content-Type: " + form_data_state.item->content_type + "\r\n\r\n";

            } else if (!form_data_state.item->value.empty()) { // field
              form_data_state.header += "\r\n\r\n";
            } else {
              pockethttp_error("[Http] FormDataItem must have either value or value_callback set");
              *read_data = pockethttp::Buffer::error;
              return false;
            }

            form_data_state.remaining = form_data_state.header.size();
          }
        
          // Send header
          size_t to_read = std::min(max_size, form_data_state.remaining);
          std::memcpy(data, form_data_state.header.c_str() + (form_data_state.header.size() - form_data_state.remaining), to_read);
          *read_data = to_read;

          if (to_read == form_data_state.remaining) {
            form_data_state.header = ""; // Clear header
            form_data_state.remaining = 0;
            form_data_state.total_sent = 0;
            form_data_state.state = pockethttp::FormDataItemStateEnum::FORMDATA_DATA; // Move to data state
          }

          return true;
        }

        case pockethttp::FormDataItemStateEnum::FORMDATA_DATA: {
          if (form_data_state.item->value_callback != nullptr) {
            pockethttp_log("[Http] Sending form-data file data for item: " << form_data_state.item->name);
            bool moreData = form_data_state.item->value_callback(
              data, 
              read_data, 
              max_size, 
              form_data_state.total_sent
            );

            form_data_state.total_sent += *read_data;

            if (!moreData) {
              form_data_state.state = pockethttp::FormDataItemStateEnum::FORMDATA_ENDING_CRLF;
              form_data_state.remaining = 2; // For the ending CRLF
            }

            return true;

          } else if (!form_data_state.item->value.empty()) { // field with value

            if (form_data_state.remaining == 0) {
              form_data_state.remaining = form_data_state.item->value.size();
            }

            size_t to_read = std::min(max_size, form_data_state.remaining);
            pockethttp_log("[Http] Sending " << to_read << " bytes of form-data field data for item: " << form_data_state.item->name);

            std::memcpy(data, form_data_state.item->value.c_str() + (form_data_state.item->value.size() - form_data_state.remaining), to_read);
            
            *read_data = to_read;
            form_data_state.remaining -= to_read;

            if (to_read == form_data_state.remaining || form_data_state.remaining == 0) {
              form_data_state.remaining = 2; // For the ending CRLF
              form_data_state.state = pockethttp::FormDataItemStateEnum::FORMDATA_ENDING_CRLF; // Move to ending CRLF state
            }

            return true;

          } else {
            pockethttp_error("[Http] FormDataItem must have either value or value_callback set");
            *read_data = pockethttp::Buffer::error;
            return false;
          }
        }

        case pockethttp::FormDataItemStateEnum::FORMDATA_ENDING_CRLF: {
          if (max_size < 2) {
            pockethttp_error("[Http] Buffer too small to write ending CRLF");
            *read_data = pockethttp::Buffer::error;
            return false;
          }

          pockethttp_log("[Http] Sending form-data ending CRLF for item: " << form_data_state.item->name);
          std::memcpy(data, "\r\n", 2);
          *read_data = 2;

          if (++form_data_state.item == req.form_data.end()) {
            form_data_state.state = pockethttp::FormDataItemStateEnum::FORMDATA_LAST_BOUNDARY;
            form_data_state.remaining = boundary.size() + 4; // For the final boundary and CRLF
          } else {
            form_data_state.state = pockethttp::FormDataItemStateEnum::FORMDATA_HEADER;
            form_data_state.remaining = 0;
          }

          return true; // More data to read
        }

        case pockethttp::FormDataItemStateEnum::FORMDATA_LAST_BOUNDARY: {
          pockethttp_log("[Http] Sending form-data last boundary");
          std::memcpy(data, ("--" + boundary + "--\r\n").c_str(), 2 + boundary.size() + 4);
          *read_data = 2 + boundary.size() + 4;
          return false; // No more data to read
        }

        default: {
          pockethttp_error("[Http] Unknown FormDataItemStateEnum state formatting form-data request body.");
          *read_data = pockethttp::Buffer::error;
          return false;
        }
      };

      return true; // More data to read
    };

    unsigned short redirect_count = 0;
    return request(remote, req.method, req.headers, res, body_callback, redirect_count, req.max_redirects, req.follow_redirects);
  }

  /* Private Methods */

  void Http::setDefaultHeaders(Headers& headers, Remote& remote) {
    pockethttp_log("[Http] Setting default headers for host: " << remote.host);
    if (!headers.has("Accept")) {
      headers.set("Accept", "*/*");
    }
    if (!headers.has("Host")) {
      headers.set("Host", remote.host);
    }
    if (!headers.has("Connection")) {
      headers.set("Connection", "keep-alive");
    }
    if (!headers.has("User-Agent")) {
      headers.set("User-Agent", "PocketHTTP/1.0");
    }
    if (!headers.has("Accept-Encoding")) {
      headers.set("Accept-Encoding", "gzip, deflate, br, identity");
    }
  }

  std::string Http::generateBoundary() {
    return BOUNDARY_PREFIX + pockethttp::random::generateRandomString(22);
  }

  size_t Http::parseStatusLine(pockethttp::Response& response, std::shared_ptr<SocketWrapper> socket, unsigned char* buffer, const size_t& buffer_size, size_t& total_bytes_read) {
    pockethttp_log("[Http] Parsing status line from socket");

    bool status_line = false;
    total_bytes_read = 0;

    while (total_bytes_read < POCKET_HTTP_CHUNK_SIZE && !status_line) {
      // Pull data from socket until CRLF is found
      size_t n = socket->receive(buffer + total_bytes_read, buffer_size - total_bytes_read, this->timeout_);
      if (n == pockethttp::Buffer::error) return pockethttp::Buffer::error;
      pockethttp_log("[Http] Received " << n << " bytes from socket.");
      if (n == 0) continue;
      total_bytes_read += n;

      // Find end of status line
      size_t end_line = pockethttp::Buffer::find(buffer, total_bytes_read, (const unsigned char*)"\r\n", 2);
      if (end_line == pockethttp::Buffer::error) return pockethttp::Buffer::error; // Continue if end of line not pulled yet

      // Parse HTTP version
      size_t offset = 0, length = 0;
      length = pockethttp::Buffer::find(buffer, total_bytes_read, (const unsigned char*)" ", 1);
      if (length == pockethttp::Buffer::error) return pockethttp::Buffer::error;
      response.version = std::string(reinterpret_cast<const char*>(buffer), length);
      offset += length + 1;

      // Parse status code
      length = pockethttp::Buffer::find(buffer + offset, total_bytes_read - offset, (const unsigned char*)" ", 1);
      if ((length + offset) == pockethttp::Buffer::error || (length + offset) > end_line) length = end_line - offset; // If no space found, assume rest is status code

      response.status = 0;
      for (size_t i = offset; i < offset + length; i++) {
        response.status = response.status * 10 + (buffer[i] - '0'); 
      }
      offset += length + 1;
    
      // Parse status text
      if (offset < end_line) {
        response.statusText = std::string(reinterpret_cast<const char*>(buffer + offset), end_line - offset);
        offset += end_line + 2; // Skip CRLF
      }

      // Move remaining data to the beginning of the buffer
      std::memmove(buffer, buffer + end_line + 2, total_bytes_read - (end_line + 2));
      total_bytes_read -= (end_line + 2);
      pockethttp_log("[Http] Moved remaining " << total_bytes_read << " bytes to the beginning of the buffer.");
      status_line = true;
      break;
    }

    if (!status_line) return pockethttp::Buffer::error;
    return total_bytes_read;
  }

  size_t Http::parseHeaders(pockethttp::Response& response, std::shared_ptr<SocketWrapper> socket, unsigned char* buffer, const size_t& buffer_size, size_t& total_bytes_read) {
    pockethttp_log("[Http] Parsing headers from socket");
    bool end_header = false;

    do {
      // Pull data from socket until CRLF is found
      size_t end_headers_pos = pockethttp::Buffer::find(buffer, total_bytes_read, (const unsigned char*)"\r\n\r\n", 4);
      
      // Keep pulling data
      if (end_headers_pos == pockethttp::Buffer::error) {
        size_t n = socket->receive(buffer + total_bytes_read, buffer_size - total_bytes_read, this->timeout_);
        if (n == pockethttp::Buffer::error) return pockethttp::Buffer::error;
        if (n == 0) continue;
        pockethttp_log("[Http] Received " << n << " bytes from socket.");
        total_bytes_read += n;
        continue;
      }

      // Parse headers
      response.headers.load(std::string(reinterpret_cast<const char*>(buffer), end_headers_pos));
      end_header = true;

      // Move any body data to the beginning of the buffer
      std::memmove(buffer, buffer + end_headers_pos + 4, total_bytes_read - (end_headers_pos + 4));
      total_bytes_read -= (end_headers_pos + 4);
      pockethttp_log("[Http] Moved remaining " << total_bytes_read << " bytes to the beginning of the buffer.");

    } while(total_bytes_read < POCKET_HTTP_CHUNK_SIZE && !end_header);

    if (!end_header) return pockethttp::Buffer::error;
    return total_bytes_read;

  }

  bool Http::handleChunked(
    pockethttp::Response& response,
    std::shared_ptr<SocketWrapper> socket,
    std::function<void(unsigned char* buffer, size_t& size)> send_body_callback,
    unsigned char* buffer,
    size_t& buffer_data_size
  ) {
    pockethttp_log("[Http] Handling chunked transfer encoding");
    bool end_chunk = false;
    unsigned short attempts = 0; 
    size_t remaining_buffer_process = buffer_data_size; // The remmaining data in the buffer to format (remove chunk headers and CRLFs)
    size_t prev_chunk_data_offset = 0;

    ChunkedResponseState status;
    
    // Repeat format-pull until buffer is full or end of chunks
    do {

      unsigned char* buf = buffer + prev_chunk_data_offset;
      pockethttp_log("[Http] Starting to process " << remaining_buffer_process << " bytes in buffer. Status: " << status.status);
      
      // Remove chunk headers and CRLFs from the buffer
      while (remaining_buffer_process > 0) {
        switch (status.status) {
          case pockethttp::ChunkedStatus::CHUNKED_STATUS_HEX: {
            if (isdigit(*buf) || isalpha(*buf)) {
              pockethttp_log("[Http] Reading chunk size hex character: " << *buf);
              status.hexbuffer[status.hexindex++] = *buf;
              buf++;
              remaining_buffer_process--;
            
            } else {
              if (status.hexindex == 0) {
                pockethttp_error("[Http] Invalid chunk size format");
                return false;
              }

              status.hexbuffer[status.hexindex] = '\0';
              status.content_length = strtol(status.hexbuffer, nullptr, 16);
              status.remaining_content_length = status.content_length;
              status.hexindex = 0;

              if (status.content_length == 0) {
                status.status = pockethttp::ChunkedStatus::CHUNKED_STATUS_DONE;
                remaining_buffer_process = 0; // Stop processing
                break;
                pockethttp_log("[Http] Reached last chunk (size 0)");
              } else {
                status.status = pockethttp::ChunkedStatus::CHUNKED_STATUS_LF;
                pockethttp_log("[Http] New chunk of size: " << status.content_length);
              }

              // Move buffer pointer forward
              buf++;
              remaining_buffer_process--;
            }

            break;
          }

          case pockethttp::ChunkedStatus::CHUNKED_STATUS_LF: {
            if (*buf == 0x0A) {
              status.status = pockethttp::ChunkedStatus::CHUNKED_STATUS_DATA;
              pockethttp_log("[Http] CRLF after chunk size found");
              
              // Move buffer data to release chunk size
              std::memmove(
                buffer + prev_chunk_data_offset,
                ++buf,
                --remaining_buffer_process
              );

              buffer_data_size = prev_chunk_data_offset + remaining_buffer_process;
              buf = buffer + prev_chunk_data_offset;
              break;
            }

            buf++;
            remaining_buffer_process--;
            break;
          }

          case pockethttp::ChunkedStatus::CHUNKED_STATUS_DATA: {
            if (status.remaining_content_length <= remaining_buffer_process) {
              // Move buffer data pointer to release chunk data + CRLF
              buf += status.remaining_content_length;
              prev_chunk_data_offset += status.remaining_content_length;
              remaining_buffer_process -= status.remaining_content_length;

              status.status = pockethttp::ChunkedStatus::CHUNKED_STATUS_POSTLF;
              status.remaining_content_length = 0;
              pockethttp_log("[Http] Chunk data of size " << status.remaining_content_length << " processed");

            } else {
              status.remaining_content_length -= remaining_buffer_process;
              buf += remaining_buffer_process;
              pockethttp_log("[Http] Partial chunk data of size " << remaining_buffer_process << " processed");

              prev_chunk_data_offset += remaining_buffer_process;
              remaining_buffer_process = 0;
            }

            break;
          }

          case pockethttp::ChunkedStatus::CHUNKED_STATUS_POSTLF: {
            if (*buf == 0x0A) {
              status.status = pockethttp::ChunkedStatus::CHUNKED_STATUS_HEX;
              pockethttp_log("[Http] CRLF after chunk data found");
            }

            buf++;
            remaining_buffer_process--;
            break;
          }

          default: {
            pockethttp_error("[Http] Unknown error in chunked response handling");
            return false;
          }
        };
      };

      pockethttp_log("[Http] Buffer formatted, calling body callback with " << prev_chunk_data_offset << " bytes of data");
      size_t before_send_available = prev_chunk_data_offset;
      send_body_callback(buffer, prev_chunk_data_offset);
      pockethttp_log("[Http] Body callback finished. Remaining " << prev_chunk_data_offset << "/" << before_send_available << " bytes of data");

      if (prev_chunk_data_offset == 0 && status.status == pockethttp::ChunkedStatus::CHUNKED_STATUS_DONE) {
        end_chunk = true;
        pockethttp_log("[Http] All chunked data processed");
        break;
      }

      // Move remaining data to the beginning of the buffer
      std::memmove(
        buffer,
        buffer + (before_send_available - prev_chunk_data_offset),
        prev_chunk_data_offset
      );
      buffer_data_size = prev_chunk_data_offset + remaining_buffer_process;

      if (attempts > POCKET_HTTP_MAX_ATTEMPTS) {
        pockethttp_error("[Http] Too many attempts processing chunked data");
        return false;
      }

      if ((POCKET_HTTP_CHUNK_SIZE - buffer_data_size) == 0) {
        pockethttp_log("[Http] Buffer full after processing chunked data");
        attempts++;
        break; // Buffer full
      } else {
        attempts = 0; // Reset attempts if there is space in the buffer
      }

      // If not all transfer data was received
      if (status.status != pockethttp::ChunkedStatus::CHUNKED_STATUS_DONE) {
        // Pull more data if needed
        size_t pulled = socket->receive(
          buffer + buffer_data_size, 
          POCKET_HTTP_CHUNK_SIZE - buffer_data_size, 
          this->timeout_
        );

        pockethttp_log("[Http] Pulled " << pulled << " bytes from socket");
        remaining_buffer_process += pulled;
        buffer_data_size += pulled;
      }

    } while (!end_chunk);

    pockethttp_log("[Http] Finished processing chunked data (" << buffer_data_size << "). End chunk (bool): " << end_chunk);
    return end_chunk;
  }

  pockethttp::HttpResult Http::request(
    pockethttp::Remote& remote,
    std::string& method,
    pockethttp::Headers& headers,
    pockethttp::Response& response,
    RequestCallback& body_callback,
    unsigned short& redirect_count,
    const unsigned short& max_redirects,
    const bool& follow_redirects
  ) {
    // Get socket
    pockethttp_log("[Http] Making request: " << method << " " << remote.path);
    std::shared_ptr<SocketWrapper> socket = SocketPool::getSocket(remote.protocol, remote.host, remote.port);
    if (!socket || socket == nullptr) {
      pockethttp_error("[Http] Failed to get socket: nullptr");
      return static_cast<pockethttp::HttpResult>(SocketPool::getLastState());
    }

    pockethttp_log("[HTTP] Has accept-encoding: \n" << headers.has("Accept-Encoding"));
    pockethttp_log("[HTTP] Headers: \n" << headers.dump());

    // Set default headers
    this->setDefaultHeaders(headers, remote);

    // Send headers
    std::string request_str = method + " " + remote.path + " HTTP/1.1\r\n" + headers.dump() + "\r\n";
    pockethttp_log("[Http] Sending request headers.");

    size_t res = socket->send(reinterpret_cast<const unsigned char*>(request_str.c_str()), request_str.size());
    if (res == pockethttp::Buffer::error) {
      pockethttp_error("[Http] Failed to send request: " << request_str);
      socket->disconnect();
      return pockethttp::HttpResult::FAILED_SEND_DATA;
    }

    // Free request_str memory
    request_str.clear(); // Empties the string
    request_str.shrink_to_fit(); // Reduces capacity to fit size (empty string)

    // Send body (if there is no body the callback will return empty and false)
    unsigned char buffer[POCKET_HTTP_CHUNK_SIZE];
    size_t read_data = 0;
    size_t total_read = 0;

    while(true) {
      read_data = 0;
      bool status = body_callback(buffer, &read_data, POCKET_HTTP_CHUNK_SIZE, total_read);
      if (!status && read_data == pockethttp::Buffer::error) {
        pockethttp_error("[Http] Request body callback error");
        socket->disconnect();
        return pockethttp::HttpResult::REQUEST_BODY_CALLBACK_ERROR;
      }

      if (!status && read_data == 0) break;
      if (read_data == 0) continue;

      if (headers.get("Transfer-Encoding") == "chunked") {
        pockethttp_log("[Http] Sending chunked body data of size: " << read_data);
        // Send chunked transfer encoding (size as hex + CRLF)
        std::ostringstream chunk_size_ss;
        chunk_size_ss << std::hex << read_data << "\r\n";

        // Append at the beginning of the buffer
        std::memmove(buffer + chunk_size_ss.str().size(), buffer, read_data);
        std::memcpy(buffer, chunk_size_ss.str().c_str(), chunk_size_ss.str().size());

        // Append CRLF at the end
        std::memcpy(buffer + chunk_size_ss.str().size() + read_data, "\r\n", 2);
        read_data += chunk_size_ss.str().size() + 2;
      }

      size_t res = socket->send(buffer, read_data);
      if (res == pockethttp::Buffer::error || res != read_data) {
        pockethttp_error("[Http] Failed to send body data. Sent " << total_read << " of " << read_data << " bytes.");
        socket->disconnect();
        return pockethttp::HttpResult::FAILED_SEND_DATA;
      }

      if (read_data > 0) total_read += read_data;
      if (!status) break;
    }

    if (headers.get("Transfer-Encoding") == "chunked") {
      if (socket->send(reinterpret_cast<const unsigned char*>("0\r\n\r\n"), 5) == pockethttp::Buffer::error) {
        pockethttp_error("[Http] Failed to send chunked transfer encoding footer");
        socket->disconnect();
        return pockethttp::HttpResult::FAILED_SEND_CHUNKED_DATA;
      }
    }

    // Parse Status line
    read_data = 0;
    read_data = this->parseStatusLine(response, socket, buffer, POCKET_HTTP_CHUNK_SIZE, read_data);
    if (read_data == pockethttp::Buffer::error) {
      pockethttp_error("[Http] Failed to parse status line");
      socket->disconnect();
      return pockethttp::HttpResult::PARSE_STATUS_LINE_FAILED;
    }

    // Parse headers
    read_data = this->parseHeaders(response, socket, buffer, POCKET_HTTP_CHUNK_SIZE, read_data);
    if (read_data == pockethttp::Buffer::error) {
      pockethttp_error("[Http] Failed to parse headers");
      socket->disconnect();
      return pockethttp::HttpResult::PARSE_HEADERS_FAILED;
    }

    // Handle redirects
    bool redirect_get = (response.status == 301 || response.status == 302 || response.status == 303);
    bool redirect_same = (response.status == 307 || response.status == 308);

    std::string location = pockethttp::utils::normalize_url(response.headers.get("Location"));
    std::string newMethod = method;
    if (redirect_get) newMethod = "GET";

    pockethttp::Remote new_remote;

    if (location.find("http://") == 0 || location.find("https://") == 0) {
      // Absolute redirect
      new_remote = pockethttp::utils::parseUrl(location);
    } else if (!location.empty()) {
      // Relative redirect
      new_remote.protocol = remote.protocol;
      new_remote.host = remote.host;
      new_remote.port = remote.port;

      if (location[0] == '/') {
        new_remote.path = location;
      } else {
        // Append to current path
        size_t last_slash = remote.path.find_last_of('/');
        if (last_slash != std::string::npos) {
          new_remote.path = remote.path.substr(0, last_slash + 1) + location;
        } else {
          new_remote.path = "/" + location;
        }
      }
    }

    headers.set("Host", new_remote.host);
    if (follow_redirects && (redirect_get || redirect_same) && !location.empty()) {

      if (redirect_count >= max_redirects) {
        pockethttp_error("[Http] Maximum redirects reached: " << max_redirects);
        socket->disconnect();
        return pockethttp::HttpResult::MAX_REDIRECTS_REACHED;
      }

      redirect_count++;
      pockethttp_log("[Http] Handling redirect to: " << location);
      socket->disconnect();

      return this->request(
        new_remote,
        newMethod,
        headers,
        response,
        body_callback,
        redirect_count,
        max_redirects,
        follow_redirects
      );
    }

    // Parse body
    if (response.headers.get("Transfer-Encoding") != "chunked" && !response.headers.has("Content-Length")) {
      if (response.version == "HTTP/1.1") return pockethttp::HttpResult::SUCCESS; // In 1.1 this means no body
    }

    pockethttp_log("[Http] Starting body parse");
    std::string encoding = response.headers.get("Content-Encoding");
    std::shared_ptr<pockethttp::Decompressor> decompressorPtr = nullptr;
    std::function<void(unsigned char* buffer, size_t& size)> send_body_callback;

    if (encoding == "gzip" || encoding == "deflate" || encoding == "br") {
      pockethttp_log("[Http] Parsing compressed body: " << encoding);

      // Handle compression algorithm
      pockethttp::DecompressionAlgorithm algorithm = pockethttp::DecompressionAlgorithm::NONE;
      if (encoding == "gzip") {
        algorithm = pockethttp::DecompressionAlgorithm::GZIP;
      } else if (encoding == "deflate") {
        algorithm = pockethttp::DecompressionAlgorithm::DEFLATE;
      } else if (encoding == "br") {
        algorithm = pockethttp::DecompressionAlgorithm::BROTLI;
      }

      // Initialize decompressor
      decompressorPtr = std::make_shared<pockethttp::Decompressor>(algorithm);
      pockethttp::DecompressionState state = decompressorPtr->init();
      if (state == pockethttp::DecompressionState::DECOMPRESS_ERROR) {
        socket->disconnect();
        return pockethttp::HttpResult::DECOMPRESS_RES_FAILED;
      }

      // Define decompression callback
      send_body_callback = [decompressorPtr, &state, &response](unsigned char* buffer, size_t& size) {
        pockethttp_log("[Http] Decompressing body data (http-request lambda): " << size << " bytes.");

        // Handle decompression and send result to user's response callback
        state = decompressorPtr->decompress(buffer, size, response.body_callback);

        // size keeps the original value
        if (state == pockethttp::DecompressionState::DECOMPRESS_ERROR) return;

        if (state == pockethttp::DecompressionState::DECOMPRESSING) {
          size = decompressorPtr->getPendingInputSize();
          return;
        }

        size = 0;
      };

    } else {
      pockethttp_log("[Http] Parsing uncompressed body");

      send_body_callback = [&response](unsigned char* buffer, size_t& size) {
        response.body_callback((const unsigned char*)buffer, (const size_t&)size);
        size = 0;
      };
    }

    // Handle transfer-encoding: chunked
    if (response.headers.get("Transfer-Encoding") == "chunked") {
      bool res_status = this->handleChunked(response, socket, send_body_callback, buffer, read_data);
      if (res_status) return pockethttp::HttpResult::SUCCESS;
      else return pockethttp::HttpResult::PARSE_CHUNKED_RES_FAILED;
    }

    bool isHttp10 = (response.version == "HTTP/1.0");
    bool isConnClose = (response.headers.get("Connection") == "close");
    bool hasContentLength = response.headers.has("Content-Length");

    size_t content_length = hasContentLength ? std::stoi(response.headers.get("Content-Length")) : 0;
    pockethttp_log("[Http] Total body size: " << content_length << "; Read: " << read_data);

    total_read = read_data;
    size_t pulled = 0;
    size_t prev_send = 0;

    do {
      if ((total_read < content_length) || !hasContentLength) {
        // Pull data
        pulled = socket->receive(buffer + read_data, POCKET_HTTP_CHUNK_SIZE - read_data, this->timeout_);
        if (pulled == pockethttp::Buffer::error) {
          pockethttp_error("[Http] Failed to receive body data.");
          socket->disconnect();
          if ((isHttp10 || isConnClose) && !hasContentLength) return pockethttp::HttpResult::SUCCESS;
          else return pockethttp::HttpResult::PARSE_RES_BODY_FAILED;
        }

        read_data += pulled;
        total_read += pulled;
      }

      prev_send = read_data; // Data in buffer before sending (callback updates read_data with remaining data)
      send_body_callback(buffer, read_data);
      if (read_data == pockethttp::Buffer::error) {
        pockethttp_error("[Http] Failed to handle body's response callback.");
        socket->disconnect();
        return pockethttp::HttpResult::PARSE_RES_BODY_FAILED;
      }

      if (read_data > 0) {
        // Move remaining data to the beginning of the buffer
        std::memmove(buffer, buffer + (prev_send - read_data), read_data);
      }

      if (hasContentLength && total_read >= content_length) break;

    } while (true);

    return pockethttp::HttpResult::SUCCESS;
  }

} // namespace pockethttp

