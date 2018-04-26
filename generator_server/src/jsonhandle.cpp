#include "jsonhandle.hpp"
#include "config.h"
#include <iostream>
#include "utils.hpp"

extern const char* mess_types[] = {
	"GET_PEER_LIST",
	"SYNC_PEER_LIST",
	"BLIND_MESSAGE",
	"INVERSE_BLIND_MESSAGE"
};

namespace bitmile {
Json::Json () : nlohmann::json() {
}

Json::Json (Json& other) : nlohmann::json((nlohmann::json)other) {
}

Json::Json (std::string data) : 
nlohmann::json(nlohmann::json::parse(data.c_str())) {
}

Json::Json (const char* data) : 
nlohmann::json(nlohmann::json::parse(data)) {

}

Json::~Json () {
}

int Json::getType() {
	std::string value = (*this)[MESSAGE_KEY_TYPE];
	int size = sizeof(mess_types)/sizeof(const char*);

	for (int i = 0; i < size; i++) {
		if (bitmile::quickCompareStr(value.c_str(), mess_types[i]))
			return i;
	}
}
} // namespace bitmile



