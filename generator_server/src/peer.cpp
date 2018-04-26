#include "peer.hpp"
#include "utils.hpp"

#define  inproc(name) "inproc://" name


namespace bitmile {

Peer::Peer () {
	setupFirst.store(true, std::memory_order_release); // <== fake value
}

Peer::~Peer() {
	// delete worker list
	while (worker_list.size()) {
		delete worker_list.front();
		worker_list.pop();
	}
}

/*
 * Just use on linux environment
 * create pipe line with ifconfig console
 */
std::string Peer::getPublicIp() {
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

bool Peer::setupWorker(zmq::context_t* context) {
	for (int i = 0; i < WORKER_THREAD_; i++) {
		worker_t* worker_ptr = new worker_t();
		worker_ptr->type = HANDLE_MESS;
		worker_ptr->id = i;
		worker_ptr->thread_ptr = (void*)new std::thread(handleMessage,this, worker_ptr, context);
		worker_list.push(worker_ptr);
	}
	return true;
}

/*
 * must init socket for router before dealer
 * this is fixed flow
 */
bool Peer::run() {
	ip = getPublicIp();
	zmq::context_t context(1);

	try {
		// setup router
		zmq::socket_t router(context, ZMQ_ROUTER);
		router.bind(Peer::concatTcpIp("*", PORT_).c_str());

		// setup dealer
		zmq::socket_t dealer(context, ZMQ_DEALER);
		dealer.bind(inproc(DEALER_NAME_));

		// create worker
		assert(setupWorker(&context));

		// establis router-dealer connection
		zmq::proxy (router, dealer, 0);

		return true;
	} catch (zmq::error_t &e) {
		std::cout << "Peer::setupRouter error: " << e.what() << std::endl;
		return false;
	}
}

/*
 * request other node sync ip of nodes in network
 * @param context_t
 * @param bitmile::Json [ip1, ip2, ip3, ip4, ...]
 */
void Peer::syncPeerListRequest (zmq::context_t* context_ptr, bitmile::Json& ips) {
	assert(context_ptr);
	zmq::socket_t client_socket(*context_ptr, ZMQ_REQ);

	/*
	* message format for sync request
	* {
	*  	"type": SYNC_PEER_LIST
	*	"auth_key": string 	<== use for check is trust mode
	*   "peer_list": []		<== list ip
	* }
	*/
	bitmile::Json mess_sync;
	mess_sync["type"] 		= bitmile::Peer::SYNC_PEER_LIST;
	mess_sync["auth_key"] 	= AUTH_KEY;
	mess_sync["peer_list"]  = ips;

	std::string dump_mess = mess_sync.dump();

	for (bitmile::Json::iterator i = ips.begin(); i != ips.end(); i++) {
		client_socket.connect(Peer::concatTcpIp(i->dump().c_str(), PORT_).c_str());
		ssend(&client_socket, dump_mess);
	}

	client_socket.close();
}

void Peer::syncPeerListResponse (zmq::socket_t* socket_ptr, bitmile::Json& messJson) {
	assert(socket_ptr);

	/*
	* message format for sync request
	* {
	*  	"type": SYNC_PEER_LIST
	*	"auth_key": string 	<== use for check is trust mode
	*   "peer_list": []		<== list ip
	* }
	*/
	std::string auth_key_str = messJson["auth_key"];
	if(!bitmile::quickCompareStr(auth_key_str.c_str(),AUTH_KEY)) // not trust, dont continuous process
		return;

	// sync list
	peer_ips.clear();
	for (bitmile::Json::iterator i = messJson["peer_list"].begin(); i != messJson["peer_list"].end(); i++) {
		peer_ips.push_back(i->dump());
	}
}

void Peer::notifyConnection (zmq::context_t* context) {
	std::cout << "Peer::getPeerListRequest " << std::endl;
	/*
	* message format for send 
	* {
	*	"type": "GET_PEER_LIST"
	*	"auth_key": string  <== use for check is trust node
	*   "from_ip": string
	* }
	*/
	bitmile::Json mess_request;
	mess_request[MESSAGE_KEY_TYPE] = mess_types[bitmile::Peer::GET_PEER_LIST];
	mess_request["auth_key"] = AUTH_KEY; // hard code for test, Should change to other value ???
	mess_request["from_ip"] = ip;

	// dump to string
	std::string dump_mess = mess_request.dump();

	// establist client socket
	zmq::socket_t req_socket(*context, ZMQ_REQ);

	// connect to boss node
	req_socket.connect(BOSS_IP);

	// notify its ip to boss instance
	ssend(&req_socket, dump_mess);
	req_socket.close();
}

void Peer::getPeerListResponse(zmq::socket_t* socket_ptr, bitmile::Json& mess) {
	std::cout << "Peer::getPeerListResponse " << std::endl;
	assert(socket_ptr);
	
	/*
	* message format for request 
	* {
	*	"type": "GET_PEER_LIST"
	*	"auth_key": string  <== use for check is trust node
	*   "from_ip": string	
	*/ 
	std::string type 			= mess["type"];
	std::string auth_key_str 	= mess["auth_key"];
	std::string from_ip 		= mess["from_ip"];

	// check sender node is trust
	if (!bitmile::quickCompareStr(auth_key_str.c_str(), AUTH_KEY))
		return;


	bitmile::Json mess_response;

	bool is_exists = false; // <== check ip was exists in list ips
	bitmile::Json array = {};

	for (std::list<std::string>::iterator i = peer_ips.begin(); i != peer_ips.end(); i++) {
	 	is_exists |= bitmile::quickCompareStr(from_ip.c_str(), (*i).c_str());
	 	array.push_back(*i);
	}

	// append sender ip to list if not exists before
	if (!is_exists) {
		std::lock_guard<std::mutex> lock(mutex);
		peer_ips.push_back(from_ip);
	}

	/*
	* message format for recv
	* {
	*  	"type": "GET_PEER_LIST"
	*	"auth_key": string 	<== use for check is trust mode
	*   "peer_list": []		<== list ip
	* }
	*/
	mess_response["type"] 		= type;
	mess_response["auth_key"] 	= AUTH_KEY;
	mess_response["peer_list"] 	= array;

	// sync list node ip with other node
	zmq::context_t context(1);
	
	if (!is_exists) {
		syncPeerListRequest(&context, array);
	}
}

void Peer::handleMessage(Peer* peer, worker_t* worker, zmq::context_t* context_ptr) {
	assert(peer);
	assert(worker);
	assert(context_ptr);

	zmq::socket_t rep_socket(*context_ptr, ZMQ_REP);

	try {
		rep_socket.connect(inproc(DEALER_NAME_));
	} catch (zmq::error_t &e) {
		std::cout << "have error when estabilsh connection " << e.what() << std::endl;
	}

	// if first run, sync peer list of other nodes in network
	if (!peer->setupFirst.load(std::memory_order_acquire)) {
		std::lock_guard<std::mutex> lock(peer->mutex);
		
		// check again
		if (peer->setupFirst.load(std::memory_order_acquire))
			goto run;

		peer->notifyConnection(context_ptr);
		peer->setupFirst.store(true, std::memory_order_release);
	}

run:
	while (1) {
		std::cout << "run() " << std::this_thread::get_id() << std::endl; 
		zmq::message_t request;
		rep_socket.recv(&request);

		// convert request data to json
		bitmile::Json mess((char*)(request.data()));

		// request peer list from other node
		if (mess.getType() == bitmile::Peer::GET_PEER_LIST) {
			peer->getPeerListResponse (&rep_socket, mess);
			continue;
		}

		// notify sync peer list from other node
		if (mess.getType() == bitmile::Peer::SYNC_PEER_LIST) {
			peer->getPeerListResponse (&rep_socket, mess);
			continue;
		}

		// request caculate blind message
		if (mess.getType() == bitmile::Peer::BLIND_MESSAGE) {
			peer->blindMessage(&rep_socket, mess);
			continue;
		}

		// request inverse blind message
		if (mess.getType() == bitmile::Peer::INVERSE_BLIND_MESSAGE) {
			peer->inverstMessage(&rep_socket, mess);
			continue;
		}
	}
}

void Peer::ssend (zmq::socket_t* socket_ptr, std::string& data) {
	zmq::message_t mess(data.size());
	memcpy(mess.data(), data.c_str(), data.size());
	socket_ptr->send(mess);
}

std::string Peer::concatTcpIp(const char* ip, const char* port) {
	return std::string("tcp://") + ip + std::string(":" PORT_);
}

/*
 * Generate blind message from random blind number
 */
void Peer::blindMessage(zmq::socket_t* socket_ptr, bitmile::Json& mess) {
	assert(socket_ptr);

	/*
	* message format for recv
	* {
	*  	"type": BLIND_MESSAGE
	* 	"identify": string  <== continuous charactor have long length  
	*	"auth_key": string 	<== use for check is trust client
	*	"data": string 	<== message use for blind process
	* }
	*/
	std::string auth_key_str = mess["auth_key"];
	if (!bitmile::quickCompareStr(auth_key_str.c_str(), AUTH_CLIENT_KEY)) // <== not trust, dont continuous process
		return;

	std::string identify = mess["identify"];
	std::string data 	 = mess["data"];

	if (!identify.size())
		return;

	std::string blind_number = numberHandle.getRandomBlindNumber();

	// TODO  something ->> start

	// <<-- end
 
	// keep ip client with this blind number for each session
	std::pair<std::string, std::string> pair(identify, blind_number);
	blind_session.insert(pair);

	// return blind message
	bitmile::Json mess_response;

	/*
	* message format for response
	* {
	*  	"type": BLIND_MESSAGE
	* 	"identify": string  <== continuous charactor have long length  
	*	"auth_key": string 	<== use for check is trust client
	*	"data": string 	<== message use for blind process
	*	"blind_server_ip": string <== ip
	* }
	*/
	mess_response["auth_key"] = AUTH_CLIENT_KEY;
	mess_response["data"] = mess["data"]; // fake, need change in future, after add logic for interact with mess data
	mess_response["blind_server_ip"] = ip;
	std::string mess_dump = mess_response.dump();
	ssend(socket_ptr,mess_dump);
}

/*
 * Inverse blind message from Inverse pair with blind number
 */
void Peer::inverstMessage(zmq::socket_t* socket_ptr,bitmile::Json& mess) {
	assert(socket_ptr);

	/*
	* message format for recv
	* {
	*  	"type": BLIND_MESSAGE
	* 	"identify": string  <== continuous charactor have long length  
	*	"auth_key": string 	<== use for check is trust client
	*	"data": string 	<== message use for blind process
	* 	"blind_server_ips": array
	*	"callback_ip" : string <== after remove all blind number, as size of blind_server_ips is empty, return raw message to callback_ip
	* }
	*/
	std::string auth_key_str = mess["auth_key"];
	if (!bitmile::quickCompareStr(auth_key_str.c_str(), AUTH_SECRET_SERVER)) // <== not trust, dont continuous process
		return;

	std::string identify = mess["identify"];
	std::string data 	 = mess["data"];

	if (!identify.size())
		return;

	// check if itself dont need join to inverse process
	// if not, then send to other node in network
	bitmile::Json::iterator i = mess["blind_server_ips"].begin();
	bool is_exists = false;

	// new array ips
	bitmile::Json array_ips = {};

	for (; i != mess["blind_server_ips"].end(); i++) {
		std::string blind_server_ip = (*i);

		if (bitmile::quickCompareStr(blind_server_ip.c_str(), ip.c_str()))
			is_exists = true;
		else 
			array_ips.push_back(blind_server_ip);
	}

	if (is_exists)
		goto send;

process:
	// TODO  something ->> start inverse process

	// <<-- end
send:
	zmq::context_t context(1);
	zmq::socket_t client_socket(context,ZMQ_REQ);

	// if array ip is empty, data was inverse success
	// send to callback ip
	if (!array_ips.size()) {
		bitmile::Json mess_send;
		mess_send["data"] = mess["data"];
		mess_send["identify"] = mess["identify"];
		mess_send["data"] = mess["data"];

		std::string data = mess_send.dump();
		std::string callback_ip = mess["callback_ip"];
		client_socket.connect(callback_ip.c_str());
		ssend(&client_socket, data);
	}
	// if no, send invert message to next node in network
	else {
		std::string next_ip = *(array_ips.begin());
		mess["blind_server_ips"] = array_ips;
		client_socket.connect(next_ip.c_str());

		std::string data = mess.dump();
		ssend(&client_socket, data);
	}

	client_socket.close();
}

} // namespace bitmile