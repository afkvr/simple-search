#ifndef _NUMBER_HANDLE_INCLUDED_
#define _NUMBER_HANDLE_INCLUDED_

#include <string>
#include <list>
#include <map>

namespace bitmile {
class NumberHandle {
	public:
		NumberHandle();
		~NumberHandle();

	public:
		void insertPairNumber(std::string blind, std::string inverse_num);
		std::string getInverseNumber(std::string blind_num, std::string modulo);

		void getListBlindNumber(std::list<std::string>&);
		std::string getRandomBlindNumber();
		void getListInverseNumber(std::list<std::string>&);
		int genRandomNum(int max);
		
	private:
		// keep list of blind number
		// first gen list when setup
		// pair key keep in string type, because this is big number
		// and easy when parse to JSON document
		// key: blind_number <-> value: inverse_of_blind_number 
		std::map<std::string, std::string> pairBlindNumbers;	
};
}

#endif