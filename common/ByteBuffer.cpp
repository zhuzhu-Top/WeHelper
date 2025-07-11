/**
 ByteBuffer
 ByteBuffer.cpp
 Copyright 2011 - 2013 Ramsey Kant

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

 Modfied 2015 by Ashley Davis (SgtCoDFish)
 */


#include "ByteBuffer.hpp"
#include "../core/BuildPackage.h"

#ifdef BB_USE_NS
namespace bb {
#endif

/**
 * ByteBuffer constructor
 * Reserves specified size in internal vector
 *
 * @param size Size (in bytes) of space to preallocate internally. Default is set in DEFAULT_SIZE
 */
ByteBuffer::ByteBuffer(uint32_t size) {
	buf.reserve(size);
	clear();
#ifdef BB_UTILITY
	name = "";
#endif
}

/**
 * ByteBuffer constructor
 * Consume an entire uint8_t array of length len in the ByteBuffer
 *
 * @param arr uint8_t array of data (should be of length len)
 * @param size Size of space to allocate
 */
ByteBuffer::ByteBuffer(uint8_t* arr, uint32_t size) {
	// If the provided array is NULL, allocate a blank buffer of the provided size
	if (arr == NULL) {
		buf.reserve(size);
		clear();
	} else { // Consume the provided array
		buf.reserve(size);
		clear();
		putBytes(arr, size);
	}

#ifdef BB_UTILITY
	name = "";
#endif
}

/**
 * Bytes Remaining
 * Returns the number of bytes from the current read position till the end of the buffer
 *
 * @return Number of bytes from rpos to the end (size())
 */
uint32_t ByteBuffer::bytesRemaining() {
	return size() - rpos;
}

/**
 * Clear
 * Clears out all data from the internal vector (original preallocated size remains), resets the positions to 0
 */
void ByteBuffer::clear() {
	rpos = 0;
	wpos = 0;
	buf.clear();
}

/**
 * Clone
 * Allocate an exact copy of the ByteBuffer on the heap and return a pointer
 *
 * @return A pointer to the newly cloned ByteBuffer. NULL if no more memory available
 */
std::unique_ptr<ByteBuffer> ByteBuffer::clone() {
	std::unique_ptr<ByteBuffer> ret = std::make_unique<ByteBuffer>(buf.size());

	// Copy data
	for (uint32_t i = 0; i < buf.size(); i++) {
		ret->put((uint8_t) get(i));
	}

	// Reset positions
	ret->setReadPos(0);
	ret->setWritePos(0);

	return ret;
}

/**
 * Equals, test for data equivilancy
 * Compare this ByteBuffer to another by looking at each byte in the internal buffers and making sure they are the same
 *
 * @param other A pointer to a ByteBuffer to compare to this one
 * @return True if the internal buffers match. False if otherwise
 */
bool ByteBuffer::equals(ByteBuffer* other) {
	// If sizes aren't equal, they can't be equal
	if (size() != other->size())
		return false;

	// Compare byte by byte
	uint32_t len = size();
	for (uint32_t i = 0; i < len; i++) {
		if ((uint8_t) get(i) != (uint8_t) other->get(i))
			return false;
	}

	return true;
}

/**
 * Resize
 * Reallocates memory for the internal buffer of size newSize. Read and write positions will also be reset
 *
 * @param newSize The amount of memory to allocate
 */
void ByteBuffer::resize(uint32_t newSize) {
	buf.resize(newSize);
	rpos = 0;
	wpos = 0;
}

/**
 * Size
 * Returns the size of the internal buffer...not necessarily the length of bytes used as data!
 *
 * @return size of the internal buffer
 */
uint32_t ByteBuffer::size() {
	return buf.size();
}

// Replacement

/**
 * Replace
 * Replace occurance of a particular uint8_t, key, with the uint8_t rep
 *
 * @param key uint8_t to find for replacement
 * @param rep uint8_t to replace the found key with
 * @param start Index to start from. By default, start is 0
 * @param firstOccuranceOnly If true, only replace the first occurance of the key. If false, replace all occurances. False by default
 */
void ByteBuffer::replace(uint8_t key, uint8_t rep, uint32_t start, bool firstOccuranceOnly) {
	uint32_t len = buf.size();
	for (uint32_t i = start; i < len; i++) {
		uint8_t data = read<uint8_t>(i);
		// Wasn't actually found, bounds of buffer were exceeded
		if ((key != 0) && (data == 0))
			break;

		// Key was found in array, perform replacement
		if (data == key) {
			buf[i] = rep;
			if (firstOccuranceOnly)
				return;
		}
	}
}
void ByteBuffer::replace(uint8_t* data, uint8_t size, uint32_t start) {
    uint32_t len = buf.size();
    memmove(&buf[start],data,size);
}


// Read Functions

uint8_t ByteBuffer::peek() const {
	return read<uint8_t>(rpos);
}

uint8_t ByteBuffer::get() const {
	return read<uint8_t>();
}

uint8_t ByteBuffer::get(uint32_t index) const {
	return read<uint8_t>(index);
}

void ByteBuffer::getBytes(uint8_t* buf, uint32_t len) const {
	for (uint32_t i = 0; i < len; i++) {
		buf[i] = read<uint8_t>();
	}
}

char ByteBuffer::getChar() const {
	return read<char>();
}

char ByteBuffer::getChar(uint32_t index) const {
	return read<char>(index);
}

double ByteBuffer::getDouble() const {
	return read<double>();
}

double ByteBuffer::getDouble(uint32_t index) const {
	return read<double>(index);
}

float ByteBuffer::getFloat() const {
	return read<float>();
}

float ByteBuffer::getFloat(uint32_t index) const {
	return read<float>(index);
}

uint32_t ByteBuffer::getInt() const {
	return read<uint32_t>();
}

uint32_t ByteBuffer::getInt(uint32_t index) const {
	return read<uint32_t>(index);
}

uint32_t ByteBuffer::getIntBE() const {
    uint32_t value = read<uint32_t>(); // 使用 read<uint32_t>() 读取数据
    uint8_t* ptr = reinterpret_cast<uint8_t*>(&value);
    std::reverse(ptr, ptr + sizeof(uint32_t)); // 反转字节顺序，转换为大端字节序
    return value;
}

uint64_t ByteBuffer::getLong() const {
	return read<uint64_t>();
}

uint64_t ByteBuffer::getLong(uint32_t index) const {
	return read<uint64_t>(index);
}

uint16_t ByteBuffer::getShort() const {
	return read<uint16_t>();
}
uint16_t ByteBuffer::getShortBE() const {
    uint16_t value = read<uint16_t>(); // 使用 read<uint16_t>() 读取数据
    uint8_t* ptr = reinterpret_cast<uint8_t*>(&value);
    std::reverse(ptr, ptr + sizeof(uint16_t)); // 反转字节顺序，转换为大端字节序
    return value;
}

uint16_t ByteBuffer::getShort(uint32_t index) const {
	return read<uint16_t>(index);
}

// Write Functions

void ByteBuffer::put(ByteBuffer* src) {
	uint32_t len = src->size();
	for (uint32_t i = 0; i < len; i++)
		append<uint8_t>(src->get(i));
}

void ByteBuffer::put(uint8_t b) {
	append<uint8_t>(b);
}

void ByteBuffer::put(uint8_t b, uint32_t index) {
	insert<uint8_t>(b, index);
}

void ByteBuffer::putBytes(uint8_t* b, uint32_t len) {
    // Insert the data one byte at a time into the internal buffer at position i+starting index
    for (uint32_t i = 0; i < len; i++)
        append<uint8_t>(b[i]);
}

void ByteBuffer::putBytes(uint8_t* b, uint32_t len, uint32_t index) {
	wpos = index;

	// Insert the data one byte at a time into the internal buffer at position i+starting index
	for (uint32_t i = 0; i < len; i++)
		append<uint8_t>(b[i]);
}
void ByteBuffer::putHexString(const std::string_view& sv){
    static auto validator = [](char c) { return (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || (c >= '0' && c <= '9'); };

    static auto char2int = [](char symbol) -> uint8_t {
        if (symbol >= '0' && symbol <= '9') {
            return static_cast<uint8_t>(symbol - '0');
        } else if (symbol >= 'A' && symbol <= 'F') {
            return static_cast<uint8_t>(symbol - 'A' + 10);
        } else if (symbol >= 'a' && symbol <= 'f') {
            return static_cast<uint8_t>(symbol - 'a' + 10);
        }

        throw std::runtime_error("Received unknown symbol");
    };

    // Checking string
    auto found = std::find_if(sv.begin(), sv.end(), [](char c) {
        return (c < 'a' || c > 'f') && (c < 'A' || c > 'F') && (c < '0' || c > '9') && (c != ' ');
    });
    if (found != sv.end()) {
        return;
    }
    // Parsing
    auto count = std::count_if(sv.begin(), sv.end(), validator);

    buf.reserve(this->wpos+count);

    bool isFirst = true;
    uint8_t firstValue = 0;

    for (auto symbol : sv) {
        if (!validator(symbol)) {
            continue;
        }

        if (isFirst) {
            firstValue = char2int(symbol);

            isFirst = false;
        } else {
            putChar(firstValue * 16 + char2int(symbol));
            isFirst = true;
        }
    }


}

void ByteBuffer::putChar(char value) {
	append<char>(value);
}

void ByteBuffer::putChar(char value, uint32_t index) {
	insert<char>(value, index);
}

void ByteBuffer::putDouble(double value) {
	append<double>(value);
}

void ByteBuffer::putDouble(double value, uint32_t index) {
	insert<double>(value, index);
}
void ByteBuffer::putFloat(float value) {
	append<float>(value);
}

void ByteBuffer::putFloat(float value, uint32_t index) {
	insert<float>(value, index);
}

void ByteBuffer::putInt(uint32_t value) {
	append<uint32_t>(value);
}

void ByteBuffer::putInt(uint32_t value, uint32_t index) {
	insert<uint32_t>(value, index);
}
void ByteBuffer::putIntBE(uint32_t value) {
    uint8_t msb = static_cast<uint8_t>((value >> 24) & 0xFF);
    uint8_t byte2 = static_cast<uint8_t>((value >> 16) & 0xFF);
    uint8_t byte3 = static_cast<uint8_t>((value >> 8) & 0xFF);
    uint8_t lsb = static_cast<uint8_t>(value & 0xFF);
    put(msb);
    put(byte2);
    put(byte3);
    put(lsb);
}
void ByteBuffer::putIntBE(uint32_t value,uint32_t index) {
        uint8_t msb = static_cast<uint8_t>((value >> 24) & 0xFF);
        uint8_t byte2 = static_cast<uint8_t>((value >> 16) & 0xFF);
        uint8_t byte3 = static_cast<uint8_t>((value >> 8) & 0xFF);
        uint8_t lsb = static_cast<uint8_t>(value & 0xFF);
        put(msb, index);
        put(byte2, index + 1);
        put(byte3, index + 2);
        put(lsb, index + 3);
}

void ByteBuffer::putLong(uint64_t value) {
	append<uint64_t>(value);
}

void ByteBuffer::putLong(uint64_t value, uint32_t index) {
	insert<uint64_t>(value, index);
}
void ByteBuffer::putLongBE(uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        uint8_t byte = (value >> (i * 8)) & 0xFF;
        put(byte);
    }
}

void ByteBuffer::putShort(uint16_t value) {
	append<uint16_t>(value);
}

void ByteBuffer::putShort(uint16_t value, uint32_t index) {
	insert<uint16_t>(value, index);
}

// Utility Functions
#ifdef BB_UTILITY
void ByteBuffer::setName(std::string n) {
	name = n;
}

std::string ByteBuffer::getName() {
	return name;
}

void ByteBuffer::printInfo() {
	uint32_t length = buf.size();
	std::cout << "ByteBuffer " << name.c_str() << " Length: " << length << ". Info Print" << std::endl;
}

void ByteBuffer::printAH() {
	uint32_t length = buf.size();
	std::cout << "ByteBuffer " << name.c_str() << " Length: " << length << ". ASCII & Hex Print" << std::endl;

	for (uint32_t i = 0; i < length; i++) {
		std::printf("0x%02x ", buf[i]);
	}

	std::printf("\n");
	for (uint32_t i = 0; i < length; i++) {
		std::printf("%c ", buf[i]);
	}

	std::printf("\n");
}

void ByteBuffer::printAscii() {
	uint32_t length = buf.size();
	std::cout << "ByteBuffer " << name.c_str() << " Length: " << length << ". ASCII Print" << std::endl;

	for (uint32_t i = 0; i < length; i++) {
		std::printf("%c ", buf[i]);
	}

	std::printf("\n");
}

void ByteBuffer::printHex() {
	uint32_t length = buf.size();
	std::cout << "ByteBuffer " << name.c_str() << " Length: 0x" << std::hex<< length << ". Hex Print" << std::endl;

	for (uint32_t i = 0; i < length; i++) {
		std::printf("%02x ", buf[i]);
	}

	std::printf("\n");
}

std::string ByteBuffer::getString() const {
	uint32_t length = buf.size();
	std::string ret;
	ret.reserve(length+1);

	for (uint32_t i = 0; i < length; i++) {

		std::string str= std::format("{:02x}",buf[i]);

		ret+=str;
	}
	return ret;
}

void ByteBuffer::printPosition() {
	uint32_t length = buf.size();
	std::cout << "ByteBuffer " << name.c_str() << " Length: " << length << " Read Pos: " << rpos << ". Write Pos: "
	        << wpos << std::endl;
}

void ByteBuffer::putShortBE(uint16_t value) {
    uint8_t msb = static_cast<uint8_t>((value >> 8) & 0xFF);
    uint8_t lsb = static_cast<uint8_t>(value & 0xFF);
    put(msb);
    put(lsb);
}

std::ostream& operator<<(std::ostream& os, const ByteBuffer& arr) {
	// Printing header
	os << "ByteArray({" << std::endl;
	os << "               #-------------#-------------#-------------#-------------#" << std::endl;
	os << "               | 00 01 02 03 | 04 05 06 07 | 08 09 0A 0B | 0C 0D 0E 0F |" << std::endl;
	os << "               #-------------#-------------#-------------#-------------#";

	// Saving states
	auto oldFlags = os.flags();
	auto oldPrec = os.precision();
	auto oldFill = os.fill();

	// Changing fill character
	os.fill('0');

	const std::vector<uint8_t>& container = arr.buf;
	const std::size_t size = container.size();

	// Calculate the width of the index
	const int indexWidth = (size > 0) ? static_cast<int>(std::log(size - 1) / std::log(16)) + 1 : 1;

	std::size_t index = 0;
	for (index = 0; index < size + (16 - (size % 16)); ++index) {
		if (!(index % 16)) {
			if (index) {
				os << "| ";
			}

			for (std::size_t asc = index - 16; asc < index; ++asc) {
				if (asc < size) {
					if (container[asc] >= uint8_t(' ') && container[asc] <= uint8_t('~')) {
						os << static_cast<char>(container[asc]);
					}
					else {
						os << '.';
					}
				}
				else {
					os << ' ';
				}
			}

			os << std::endl << "    0x";
			os.width(8);
			os << std::hex << index << ' ';
		}

		if (!(index % 4)) {
			os << "| ";
		}

		if (index < size) {
			os.width(2);
			os << std::uppercase << std::hex << static_cast<int>(container[index]) << ' ';
		}
		else {
			os << "   ";
		}
	}

	if (index) {
		os << "| ";
	}

	for (std::size_t asc = index - 16; asc < index; ++asc) {
		if (asc < size) {
			if (container[asc] >= uint8_t(' ') && container[asc] <= uint8_t('~')) {
				os << static_cast<char>(container[asc]);
			}
			else {
				os << '.';
			}
		}
		else {
			os << ' ';
		}
	}

	os << std::endl
		<< std::nouppercase << "               #-------------#-------------#-------------#-------------#" << std::endl
		<< "}, Length: 0x" << std::hex << size << ", Capacity: 0x" << std::hex << container.capacity() << ')' << std::endl;

	os.flags(oldFlags);
	os.precision(oldPrec);
	os.fill(oldFill);

	return os;
}




#ifdef BB_USE_NS
}
#endif

#endif
