//
// Created by 28264 on 2023/5/27.
//

#ifndef WEHELPER_PUB_INCLUDE_H
#define WEHELPER_PUB_INCLUDE_H

#include <vector>
#include <deque>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <bitset>
#include <future>
#include <regex>
#include <map>
#include "spdlog/spdlog.h"
#include "spdlog/fmt/bin_to_hex.h"
#include "spdlog/fmt/ranges.h"
#include <nlohmann/json.hpp>


#include <stdlib.h>
#include <string.h>

#include <iomanip> //fmt





#define LOG_LEVEL_DEBUG
//#define MMTLS_DEBUG
//AES CBC解密
//解压缩
//内部包头打印


#ifdef LOG_LEVEL_DEBUG // 判断是否定义了 MY_DEBUG 宏
#define LOGD(msg,...) spdlog::debug(msg, ##__VA_ARGS__) // 输出 DEBUG 级别的日志
#else
#define LOGD(msg,...) // 不输出日志
#endif

#ifdef MMTLS_DEBUG // 判断是否定义了 MY_DEBUG 宏
#define MMTLSLOG(msg,...) spdlog::debug(msg, ##__VA_ARGS__) // 输出 DEBUG 级别的日志
#else
#define MMTLSLOG(msg,...) // 不输出日志
#endif





#endif //WEHELPER_PUB_INCLUDE_H
