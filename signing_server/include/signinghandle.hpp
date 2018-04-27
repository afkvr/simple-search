#ifndef _NUMBER_HANDLE_INCLUDED_
#define _NUMBER_HANDLE_INCLUDED_

#include <string>
#include <list>
#include <map>

namespace bitmile {
class SigningHandle {
	public:
		SigningHandle();
		~SigningHandle();

	public:
		std::string getSigningNumber() const;
		void randomSigningNumber();
		std::string signingCaculator(std::string& data) const; 
	private:
		// keep signing number
		// first gen list when setup
		// number keep in string type, because this is big number
		// and easy when parse to JSON document
		std::string signing_number;	
};
}

#endif