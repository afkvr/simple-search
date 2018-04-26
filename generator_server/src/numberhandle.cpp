#include "config.h"
#include "numberhandle.hpp"
#include <string>
#include <iostream>

// for random number
#include <ctime>
#include <cstdlib>

namespace bitmile {

NumberHandle::NumberHandle () {
}

NumberHandle::~NumberHandle () {
}

void NumberHandle::insertPairNumber(std::string blind, std::string inverse_num) {
	pairBlindNumbers.insert(std::pair<std::string, std::string>(blind, inverse_num));
}

std::string NumberHandle::getInverseNumber(std::string blind_num, std::string modulo) {
	std::map<std::string, std::string>::iterator i = pairBlindNumbers.find(blind_num);

	if (pairBlindNumbers.find(blind_num) == pairBlindNumbers.end()) {
		return std::string(UNKNOW_NUM); // hard code for unknow number
	}

	return i->second;
}

void NumberHandle::getListBlindNumber(std::list<std::string>& keys) {
	std::map<std::string,std::string>::iterator i = pairBlindNumbers.begin();

	while (i != pairBlindNumbers.end()) {
		keys.push_back(i->first);
		i++;
	}
}

void NumberHandle::getListInverseNumber(std::list<std::string>& values) {
	std::map<std::string,std::string>::iterator i = pairBlindNumbers.begin();

	while (i != pairBlindNumbers.end()) {
		values.push_back(i->second);
		i++;
	}
}

std::string NumberHandle::getRandomBlindNumber() {
	if (!pairBlindNumbers.size())
		return std::string("");

	srand(time(NULL));
	int randomIndex = rand() % pairBlindNumbers.size();
	std::map<std::string,std::string>::iterator i = pairBlindNumbers.begin();
	
	while (randomIndex) {
		randomIndex--;
		i++;
	}
	
	return i->first;
}

}