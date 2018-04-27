#include <zmq.hpp>
#include <string>
#include <sstream>
#include <iostream>

int main ()
{
    //  Prepare our context and socket
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_REQ);

    std::cout << "Connecting to hello world server…" << std::endl;
    socket.connect ("tcp://localhost:5555");

    //  Do 10 requests, waiting each time for a response
    for (int request_nbr = 0; request_nbr != 100; request_nbr++) {
        //zmq::message_t request (10);

	std::string data ("{	\
				\"type\": \"GET_PEER_LIST\", \
				\"auth_key\": \"generate_server\", \
				\"from_ip\": \"192.168.1.1\" \
            		}");	
	//data << request_nbr;
	//sprintf(data, request_nbr);
	
	zmq::message_t request(data.size());
        memcpy (request.data(), data.c_str(), data.size());
        std::cout << "data " << request_nbr  << std::endl;
        socket.send (request);

        //  Get the reply.
        zmq::message_t reply;
        socket.recv (&reply);
        std::cout << "Received  " << (char*)reply.data() << std::endl;
    }
    return 0;
}

