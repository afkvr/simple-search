#include "jsonhandle.hpp"
#include "config.h"
#include <iostream>
#include <string>
#include "utils.hpp"

namespace bitmile {
JsonHandle::JsonHandle () : nlohmann::json() {
}

JsonHandle::JsonHandle (JsonHandle& other) : nlohmann::json((nlohmann::json)other) {
}

JsonHandle::JsonHandle (std::string data) : 
nlohmann::json(nlohmann::json::parse(data.c_str())) {
}

JsonHandle::JsonHandle (const char* data) : 
nlohmann::json(nlohmann::json::parse(data)) {

}

JsonHandle::~JsonHandle () {
}

int JsonHandle::getType() {
	std::string value = (*this)[MESSAGE_KEY_TYPE];
	int int_value = std::stoi(value);
	return int_value;
}
} // namespace bitmile



