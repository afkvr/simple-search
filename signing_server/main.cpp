
#include <zmq.hpp>

#include <iostream>
#include "include/config.h"
#include "include/peer.hpp"
#include "jsonhandle.hpp"

int main(int argc, char* argv[]) {
	bitmile::Peer peer;
	peer.run();
	return 0;
}