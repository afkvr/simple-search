#include <zmq.hpp>
#include <string>
#include <sstream>
#include <iostream>

/*
 * Just use on linux environment
 * create pipe line with ifconfig console
 */
std::string getPublicIp() {
	std::string ip = "";
    	FILE * fp = popen("ifconfig", "r");
    	if (fp) {
        char *p = NULL, *e;
        size_t n;
        while ((getline(&p, &n, fp) > 0) && p) {
            if (p = strstr(p, "inet addr:")) {
                p += 10;
                if (e = strchr(p, ' ')) {
                    *e = '\0';
                    ip = std::string(p);
                    break;
                }
            }
        }
    }

    pclose(fp);
    return ip;
}


int main ()
{
    //  Prepare our context and socket
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_REQ);

    std::cout << "Connecting to hello world server…" << std::endl;
    socket.connect ("tcp://192.168.1.95:5555"); // <== boss ip

    //  Do 10 requests, waiting each time for a response
    //for (int request_nbr = 0; request_nbr != 100; request_nbr++) {
        //zmq::message_t request (10);

	std::string data ("{\"identify\":\"thangnt123\",\"type\":\"CLIENT_SIGNING_MESSAGE\",\"auth_key\":\"auth_client\",\"callback_ip\":\"tcp://192.168.1.95:5555\",\"data\":\"this is some data\"}");	
	//data << request_nbr;
	//sprintf(data, request_nbr);
	std::cout << "message content: " << data << std::endl;	
	zmq::message_t request(data.size()+1);
        memcpy (request.data(), data.c_str(), data.size());
//        std::cout << "data " << request_nbr  << std::endl;
        socket.send (request);

	char* char_ptr = (char*)request.data();
	char_ptr[data.size()] = '\0';

        //  Get the reply.
        zmq::message_t reply;
        socket.recv (&reply);
        std::cout << "Received  " << (char*)reply.data() << std::endl;
    //}
	socket.close();
    return 0;
}

