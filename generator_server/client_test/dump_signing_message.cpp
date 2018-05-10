#include <zmq.hpp>
#include <string>
#include <sstream>
#include <iostream>
#include "json.hpp"

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
    socket.connect ("tcp://192.168.1.70:5555"); // <== boss ip

    // fake
	 nlohmann::json signing_request;
     signing_request["identify"] = "thangnt123";
     signing_request["type"] = "3";
     signing_request["auth_key"] = "auth_client";
     signing_request["callback_ip"] = "tcp://192.168.1.95:5555";

    nlohmann::json upload_data;
    upload_data["owner_address"] = "ether address";
    upload_data["doc_id"] = "1";
    upload_data["elastic_doc_id"] = "2";
    upload_data["data"] = "aGVsbG8=";
    upload_data["data_size"] = 5;

    std::vector<std::string> keys = { "c" , "d"};
    upload_data["keywords"] = keys;

    signing_request["data"] = upload_data.dump();

    std::string signing_data_str = signing_request.dump();
    std::cout << "message content: " << signing_data_str << std::endl; 

	zmq::message_t request(signing_data_str.size()+1);
    memcpy (request.data(), signing_data_str.c_str(), signing_data_str.size());
    socket.send (request);

	char* char_ptr = (char*)request.data();
	char_ptr[signing_data_str.size()] = '\0';

    //  Get the reply.
    zmq::message_t reply;
    socket.recv (&reply);
    std::cout << "Received  " << (char*)reply.data() << std::endl;

	socket.close();
    return 0;
}

