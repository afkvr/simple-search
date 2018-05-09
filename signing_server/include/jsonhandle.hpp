/*
 * Keep message data in json format when send and recv throught network
*/
#ifndef _JSON_HPP_INCLUDED_
#define _JSON_HPP_INCLUDED_

#include "nlohmann/json.hpp"

#define MESSAGE_KEY_TYPE "type"

namespace bitmile {
class JsonHandle : public nlohmann::json {
	public:
		JsonHandle();
		JsonHandle(JsonHandle& other);
		JsonHandle(std::string data);
		JsonHandle(const char*);
		
		~JsonHandle();

	public:
		int getType();
};
}

#endif