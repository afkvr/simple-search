#include "config.h"
#include "numberhandle.hpp"
#include <string>
#include <iostream>

// for random number
#include <random>
#include <limits>
#include <cstdlib>

namespace bitmile {

NumberHandle::NumberHandle () {
	// gen fake data
	for (int i =0; i < 100; i++) {
		std::pair<std::string, std::string> pair (std::to_string(i), std::to_string(100 - i));
		pairBlindNumbers.insert(pair);
	}
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

	int randomIndex = genRandomNum(pairBlindNumbers.size() -1);
	std::map<std::string,std::string>::iterator i = pairBlindNumbers.begin();
	
	while (randomIndex) {
		randomIndex--;
		i++;
	}

	std::cout << "NumberHandle::getRandomBlindNumber blindNumber " << i->first << std::endl; 
	
	return i->first;
}

int NumberHandle::genRandomNum(int max) {
	std::random_device rd;

	std::default_random_engine e1(rd());
	std::uniform_int_distribution<int> distribution(0, max);

	int random_val = distribution(e1);
	std::cout << "Peer::genVoteNumber " << random_val << std::endl;
	return random_val;
}

}