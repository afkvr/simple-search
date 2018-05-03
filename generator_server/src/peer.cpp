#include "peer.hpp"
#include "utils.hpp"

#define  inproc(name) "inproc://" name
#define  END_OF_STRING '\0'

namespace bitmile {

Peer::Peer () {
	setupFirst.store(false, std::memory_order_release); // <== fake value
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
	mess_sync["type"] 		= mess_types[SYNC_PEER_LIST];
	mess_sync["auth_key"] 	= AUTH_KEY;
	mess_sync["peer_list"]  = ips;

	broadcastMessage(mess_sync);
}

void Peer::syncPeerListResponse (zmq::socket_t* socket_ptr, bitmile::Json& messJson) {
	std::cout << "Peer::syncPeerListResponse mess dump " << messJson.dump() << std::endl;
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
		std::cout << "Peer::syncPeerListResponse ip " << i->get<std::string>() << std::endl;
		peer_ips.push_back(i->get<std::string>().c_str());
	}
}

void Peer::notifyConnection (zmq::context_t* context) {
	std::cout << "Peer::NOTYFY_CONNECTION " << std::endl;
	/*
	* message format for send 
	* {
	*	"type": "GET_PEER_LIST"
	*	"auth_key": string  <== use for check is trust node
	*   "from_ip": string
	* }
	*/
	bitmile::Json mess_request;
	mess_request[MESSAGE_KEY_TYPE] = mess_types[GET_PEER_LIST];
	mess_request["auth_key"] = AUTH_KEY; // hard code for test, Should change to other value ???
	mess_request["from_ip"] = ip;

	// dump to string
	std::string dump_mess = mess_request.dump();

	// establist client socket
	zmq::socket_t req_socket(*context, ZMQ_REQ);

	// connect to boss node
	req_socket.connect(bitmile::Peer::concatTcpIp(BOSS_IP,PORT_).c_str());

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
		array.push_back(from_ip);
	}

	/*
	* message format for recv
	* {
	*  	"type": "GET_PEER_LIST"
	*	"auth_key": string 	<== use for check is trust mode
	*   "peer_list": []		<== list ip
	* }
	*/
	mess_response["type"] 		= mess["type"];
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
		
		// ignore if boss ip is itself
		if (bitmile::quickCompareStr(peer->ip.c_str(), BOSS_IP)) {
			peer->peer_ips.push_back(peer->ip);
			peer->setupFirst.store(true, std::memory_order_release);
			goto run;
		}

		// check again
		if (peer->setupFirst.load(std::memory_order_acquire))
			goto run;

		peer->notifyConnection(context_ptr);
		peer->setupFirst.store(true, std::memory_order_release);
	}

run:
	while (1) {
		zmq::message_t request;
		rep_socket.recv(&request);

		std::cout << "handle message " << (char*)request.data() << std::endl;
		// convert request data to json
		bitmile::Json mess((char*)(request.data()));
		int mess_type = mess.getType();

		// request peer list from other node
		if (mess_type == GET_PEER_LIST) {
			peer->getPeerListResponse (&rep_socket, mess);
		}

		// notify sync peer list from other node
		else if (mess_type == SYNC_PEER_LIST) {
			peer->syncPeerListResponse (&rep_socket, mess);
		}

		// request blind number from client device
		else if (mess_type == CLIENT_BLIND_NUMBER_REQUEST) {
			peer->clientBlindNumberRequest(&rep_socket, mess);
			continue;
		}

		// request blind number from other node
		else if (mess_type == PEER_BLIND_NUMBER_REQUEST) {
			peer->peerBlindNumberRequest(&rep_socket, mess);
			continue;
		}

		// request caculate blind message
		else if (mess_type == BLIND_MESSAGE) {
			peer->blindMessage(&rep_socket, mess);
		}

		// request inverse blind message
		else if (mess_type == INVERSE_BLIND_MESSAGE) {
			peer->inverseMessage(&rep_socket, mess);
		}

		zmq::message_t reponse(1);
		rep_socket.send(reponse);
	}
}


/*
 * Generate and return blind number to client
 */
void Peer::peerBlindNumberRequest(zmq::socket_t* socket_ptr, bitmile::Json& mess) {
	std::cout << "Peer::peerBlindNumberRequest start" << mess.dump() << std::endl;
	assert(socket_ptr);

	/*
	* message format for req
	* {
	*  	"type": PEER_BLIND_NUMBER_REQUEST
	* 	"identify": string  <== continuous charactor have long length  
	*	"auth_key": string 	<== use for check is trust peer
	* }
	*/
	std::string auth_key_str = mess["auth_key"];
	if (!bitmile::quickCompareStr(auth_key_str.c_str(), AUTH_KEY)) // <== not trust, dont continuous process
		return;

	std::string identify = mess["identify"];

	if (!identify.size())
		return;

	// logic for generate blind at here
	std::string blind_number = numberHandle.getRandomBlindNumber();
	std::map<std::string, std::string>::iterator i = blind_session.find(identify);

	// keep client ip with this blind number for each session
	// not exists, create new
	if (i == blind_session.end()) {
		std::pair<std::string, std::string> pair(identify, blind_number);
		blind_session.insert(pair);
	}
	// if exists, repleace with new value
	else {
		i->second = blind_number;
	}

	std::cout << "Peer::peerBlindNumberRequest begin response" << std::endl;
	// response 
	{
		/*
		* message format for rep
		* {
		*  	"type": PEER_BLIND_NUMBER_RESPONSE
		*	"auth_key": string 	<== use for check is trust peer
		*	"blind_number": string <== blind value
		* }
		*/
		bitmile::Json blind_rep;
		blind_rep["type"] = mess_types[PEER_BLIND_NUMBER_RESPONSE];
		blind_rep["auth_key"] = AUTH_KEY;
		blind_rep["blind_number"] = blind_number;

		std::string dump_mess = blind_rep.dump();
		ssend(socket_ptr, dump_mess);
	}

	std::cout << "Peer::peerBlindNumberRequest end" << std::endl;
}

void Peer::ssend (zmq::socket_t* socket_ptr, std::string& data) {
	long long mess_real_size = data.size()+1; // <== one byte for end charator
	zmq::message_t mess(mess_real_size);
	memcpy(mess.data(), data.c_str(), data.size());

	// set end charator for string
	char* char_ptr = (char*)mess.data();
	char_ptr[data.size()] = END_OF_STRING;

	(*socket_ptr).send(mess);
}

std::string Peer::concatTcpIp(const char* ip, const char* port) {
	return std::string("tcp://") + ip + std::string(":") + std::string(port);
}


void Peer::broadcastMessage(bitmile::Json& mess) {
	std::cout << "Peer::broadcastMessage mess " << mess.dump() << std::endl;
	std::string mess_dump = mess.dump();

	std::list<std::string>::iterator i = peer_ips.begin();
	zmq::context_t context(1);
	std::string tcpIp;

	for (;i != peer_ips.end(); i++) {
		// dont send event to itself
		if (bitmile::quickCompareStr((*i).c_str(), ip.c_str()))
			continue;

		zmq::socket_t client_socket(context, ZMQ_REQ);
		tcpIp = Peer::concatTcpIp((*i).c_str(),PORT_);
		std::cout << "Peer::broadcastMessage ip  " << tcpIp << std::endl;
		client_socket.connect(tcpIp.c_str());
		ssend(&client_socket, mess_dump);
		client_socket.close();
	}
}


/*
 * Generate and return blind number to client
 */
void Peer::clientBlindNumberRequest(zmq::socket_t* socket_ptr, bitmile::Json& mess) {
	assert(socket_ptr);
	/*
	* message format for recv
	* {
	*  	"type": CLIENT_BLIND_NUMBER_REQUEST
	* 	"identify": string  <== continuous charactor have long length  
	*	"auth_key": string 	<== use for check is trust client
	* }
	*/
	std::string auth_key_str = mess["auth_key"];
	if (!bitmile::quickCompareStr(auth_key_str.c_str(), AUTH_CLIENT_KEY)) // <== not trust, dont continuous process
		return;

	std::string identify = mess["identify"];

	if (!identify.size())
		return;

	// logic for generate blind at here
	std::string blind_number = numberHandle.getRandomBlindNumber();

	std::map<std::string, std::string>::iterator i = blind_session.find(identify);

	// keep client ip with this blind number for each session
	// not exists, create new
	if (i == blind_session.end()) {
		std::pair<std::string, std::string> pair(identify, blind_number);
		blind_session.insert(pair);
	}
	// if exists, repleace with new value
	else {
		i->second = blind_number;
	}

	// send broadcast to other node for gen blind number
	bitmile::Json blind_array = {}; // list blind number will send back to client device
	blind_array.push_back(blind_number);
	
	{
		/*
		* message format for req
		* {
		*  	"type": PEER_BLIND_NUMBER_REQUEST
		* 	"identify": string  <== continuous charactor have long length  
		*	"auth_key": string 	<== use for check is trust peer
		* }
		*/
		bitmile::Json blind_req;
		blind_req["type"] = mess_types[PEER_BLIND_NUMBER_REQUEST];
		blind_req["identify"] = identify;
		blind_req["auth_key"] = AUTH_KEY;

		std::string mess_dump = blind_req.dump();

		zmq::context_t context(1);
		zmq::socket_t socket(context, ZMQ_REQ);

		// send to other node
		for (std::list<std::string>::iterator i = peer_ips.begin(); i != peer_ips.end(); i++) {
			// dont process if this is itself
			if (bitmile::quickCompareStr((*i).c_str(), ip.c_str()))
				continue;

			// connect
			socket.connect(concatTcpIp((*i).c_str(),PORT_).c_str());
			
			// send message
			ssend(&socket, mess_dump);
			std::cout << "Peer::clientBlindNumberRequest  dump mess request" << mess_dump.data() << std::endl;

			// recv response
			zmq::message_t mess_reponse;
			socket.recv(&mess_reponse);
			
			/*
			* message format for rep
			* {
			*  	"type": PEER_BLIND_NUMBER_RESPONSE
			*	"auth_key": string 	<== use for check is trust peer
			*	"blind_number": string <== blind value
			* }
			*/
			bitmile::Json reponse((char*)mess_reponse.data());
			std::cout << "Peer::clientBlindNumberRequest  dump mess response " << reponse.dump() << std::endl;
			std::string blind_num = reponse["blind_number"];
			blind_array.push_back(blind_num);

			// close connection
			socket.close();
		}
	}

	// blind message for respone to client
	{
		bitmile::Json blind_rep;

		/*
		* message format for rep
		* {
		*  	"type": PEER_BLIND_NUMBER_RESPONSE
		*	"auth_key": string 	<== use for check is trust peer
		*	"blind_numbers": string <== blind value
		* }
		*/
		blind_rep["type"] = mess_types[CLIENT_BLIND_NUMBER_RESPONSE];
		blind_rep["auth_key"] = AUTH_KEY;
		blind_rep["blind_numbers"] = blind_array;

		std::string dump_mess = blind_rep.dump();
		ssend(socket_ptr, dump_mess);
	}
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
void Peer::inverseMessage(zmq::socket_t* socket_ptr,bitmile::Json& mess) {
	std::cout << "Peer::inverseMessage start " << mess.dump() << std::endl;
	assert(socket_ptr);

	/*
	* message format for recv
	* {
	*  	"type": INVERSE_BLIND_MESSAGE
	* 	"identify": string  <== continuous charactor have long length  
	*	"auth_key": string 	<== use for check is trust client
	*	"data": string 	<== message use for blind process
	* 	"blind_server_ips": array
	*	"callback_ip" : string <== after remove all blind number, as size of blind_server_ips is empty, return raw message to callback_ip
	* }
	*/
	std::string auth_key_str = mess["auth_key"];
	if (!bitmile::quickCompareStr(auth_key_str.c_str(), AUTH_SINGING_SERVER)) // <== not trust, dont continuous process
		return;

	std::string identify = mess["identify"];
	std::string data 	 = mess["data"];

	if (!identify.size())
		return;

	bitmile::Json array_ips = {};

	// loop is bad, need change in future
	for (bitmile::Json::iterator i = mess["blind_server_ips"].begin(); i != mess["blind_server_ips"].end(); i++) {
		array_ips.push_back(i->get<std::string>());
	}

 	// need check for change login in future
	array_ips.push_back(ip);

process:
	// TODO  something ->> start inverse process

	// <<-- end
send:
	zmq::context_t context(1);
	zmq::socket_t client_socket(context,ZMQ_REQ);

	// if array ip is empty, data was inverse success
	// send to callback ip

	if (array_ips.size() == peer_ips.size()) {
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
		std::string next_ip;
		bool found = false;

		// find ip not exists in array_ips
		for (std::list<std::string>::iterator i = peer_ips.begin(); i != peer_ips.end(); i++)
		{
			for (bitmile::Json::iterator j = array_ips.begin(); j != array_ips.end(); j++) {
				if(bitmile::quickCompareStr(i->c_str(), j->get<std::string>().c_str())) {
					std::cout << "compare " << *i << " and " << j->get<std::string>() << std::endl;
					break;
				}

				found = true;
			}

			if (!found)
				continue;

			next_ip =  *i;
			break;
		}

		std::cout << "next ip " << next_ip << std::endl;
		mess["blind_server_ips"] = array_ips;
		client_socket.connect(bitmile::Peer::concatTcpIp(next_ip.c_str(),PORT_).c_str());

		std::string data = mess.dump();
		ssend(&client_socket, data);
	}

	client_socket.close();

	// clear session
	blind_session.erase(identify);
}

} // namespace bitmile