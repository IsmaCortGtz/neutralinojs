#ifndef NEU_NET_H
#define NEU_NET_H

#include <string>

#include "lib/json/json.hpp"
#include <asio/thread_pool.hpp>

using json = nlohmann::json;
using namespace std;

namespace net {

extern asio::thread_pool _pool;

namespace controllers {

json resolveHost(const json &input);
json fetch(const json &input);

} // namespace controllers

} // namespace net

#endif // define NEU_NET_H