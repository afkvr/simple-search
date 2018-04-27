#include "config.h"
#include "signinghandle.hpp"
#include <string>
#include <iostream>

// for random number
#include <ctime>
#include <cstdlib>

namespace bitmile {

SigningHandle::SigningHandle () {
}

SigningHandle::~SigningHandle () {
}

std::string SigningHandle::getSigningNumber () const{
	return signing_number;
}

void SigningHandle::randomSigningNumber() {
	
}

std::string SigningHandle::signingCaculator(std::string& data) const{
	// TODO
	return data; // <== fake
}
}