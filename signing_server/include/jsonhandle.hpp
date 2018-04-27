/*
 * Keep message data in json format when send and recv throught network
*/
#ifndef _JSON_HPP_INCLUDED_
#define _JSON_HPP_INCLUDED_

#include "nlohmann/json.hpp"

#define MESSAGE_KEY_TYPE "type"

namespace bitmile {
class Json : public nlohmann::json {
	public:
		Json();
		Json(Json& other);
		Json(std::string data);
		Json(const char*);
		
		~Json();

	public:
		int getType();
};
}

#endif