#include "peer.hpp"
#include "utils.hpp"

// for rand number
#include <ctime>
#include <cstdlib>

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
	mess_sync["type"] 		= SYNC_PEER_LIST;
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
	mess_request[MESSAGE_KEY_TYPE] = mess_types[GET_PEER_LIST];
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
		zmq::message_t request;
		rep_socket.recv(&request);

		// convert request data to json
		bitmile::Json mess((char*)(request.data()));

		// request peer list from other node
		if (mess.getType() == GET_PEER_LIST) {
			peer->getPeerListResponse (&rep_socket, mess);
			continue;
		}

		// notify sync peer list from other node
		if (mess.getType() == SYNC_PEER_LIST) {
			peer->getPeerListResponse (&rep_socket, mess);
			continue;
		}

		// request for new vote, find one in group will use for decrypt process
		if (mess.getType() == VOTE_MESSAGE) {
			peer->voteRequest(&rep_socket, mess);
			continue;
		}

		// request signing message from client app
		if (mess.getType() == CLIENT_SIGNING_MESSAGE) {
			peer->clientSigningMessageReq(&rep_socket, mess);
			continue;
		}

		// request signing message from peer node in network
		if (mess.getType() == PEER_SIGNING_MESSAGE) {
			peer->peerSigningMessageReq(&rep_socket, mess);
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
void Peer::clientSigningMessageReq(zmq::socket_t* socket_ptr, bitmile::Json& mess) {
	assert(socket_ptr);

	/*
	* message format for recv
	* {
	*  	"type": CLIENT_SIGNING_MESSAGE_REQ
	*	"identity": string  <== continuous charactor have long length
	* 	"call_back_ip": string  <== after signing process successful, send signing data back to call_back_ip 
	*	"auth_key": string 	<== use for check is trust client
	*	"data": string 	<== message use for blind process
	* }
	*/
	std::string auth_key_str = mess["auth_key"];

	// if not trust, dont continuous process
	if (!bitmile::quickCompareStr(auth_key_str.c_str(), AUTH_CLIENT_KEY) || 
		!bitmile::quickCompareStr(auth_key_str.c_str(), AUTH_KEY)) 
		return;

	std::string identify = mess["identify"];
	std::string data 	 = mess["data"];

	if (!identify.size())
		return;

	// TODO  something ->> start
	std::string signing_data = signingHandle.signingCaculator(data);
	// <<-- end
 
	// keep ip client with this signing data for each session
	std::pair<std::string, std::string> pair(identify, signing_data);
	
	// lock for insert new session
	{
		std::lock_guard<std::mutex> guard(mutex);
		signing_session.insert(pair);
	}

 	// notify to other node in network for create singing data 
	{
		bitmile::Json mess_peer_request;

		/*
		* message format for response
		* {
		*  	"type": PEER_SIGNING_MESSAGE
		* 	"identify": string  <== continuous charactor have long length  
		*	"auth_key": string 	<== use for check is trust client
		* 	"call_back_ip": string  <== after signing process successful, send signing data back to call_back_ip 
		*	"data": string 	<== message use for blind process
		* }
		*/
		mess_peer_request["type"] = mess_types[PEER_SIGNING_MESSAGE];
		mess_peer_request["identify"] = mess["identify"];
		mess_peer_request["auth_key"] = AUTH_KEY;
		mess_peer_request["data"] = mess["data"]; // fake, need change in future, after add logic for interact with mess data
		broadcastMessage(mess_peer_request);
	}

	// gen vote number for itself
	long long vote_num = bitmile::Peer::genVoteNumber();
	std::pair<std::string, long long> ip_vote(ip, vote_num);

	std::map<std::string, std::map<std::string, long long>>::iterator i = challenge_numbers.find(identify);
	
	if (i == challenge_numbers.end()){
		std::pair<std::string, std::map<std::string, long long>> pair_challenge(identify, std::map<std::string, long long>());
		pair_challenge.second.insert(ip_vote);
		challenge_numbers.insert(pair_challenge);
	}
	else {
		i->second.insert(ip_vote);
	}

	// broadcat vote number to all node in network
	{
		/*
		* message format for response
		* {
		*  	"type": VOTE_MESSAGE
		*	"identity" : string <== continuous charactor have long length
		* 	"from_ip": string  
		*	"auth_key": string 	<== use for check is trust client
		* 	"vote" : string <== vote number use for compare 
		* }
		*/
		bitmile::Json mess_peer_request;
		mess_peer_request["type"] = mess_types[VOTE_MESSAGE];
		mess_peer_request["identify"] = mess["identify"];
		mess_peer_request["auth_key"] = AUTH_KEY;
		mess_peer_request["from_ip"] = ip;
		mess_peer_request["vote"] =  std::to_string(vote_num);
		broadcastMessage(mess_peer_request);
	}
}

void Peer::broadcastMessage(bitmile::Json& mess) {
	std::string mess_dump = mess.dump();

	std::list<std::string>::iterator i = peer_ips.begin();
	zmq::context_t context(1);
	zmq::socket_t client_socket(context, ZMQ_REQ);
	std::string tcpIp;

	for (;i != peer_ips.end(); i++) {

		// dont send event to itself
		if (bitmile::quickCompareStr((*i).c_str(), ip.c_str()))
			continue;

		tcpIp = Peer::concatTcpIp((*i).c_str(),PORT_);
		client_socket.connect(tcpIp.c_str());
		ssend(&client_socket, mess_dump);
		client_socket.close();
	}
}

/*
 *  Request signing message from other peer
 */
void Peer::peerSigningMessageReq(zmq::socket_t* socket_ptr,bitmile::Json& mess) {
	assert(socket_ptr);

	/*
	* message format for response
	* {
	*  	"type": PEER_SIGNING_MESSAGE
	* 	"identify": string  <== continuous charactor have long length  
	*	"auth_key": string 	<== use for check is trust client
	* 	"call_back_ip": string  <== after signing process successful, send signing data back to call_back_ip 
	*	"data": string 	<== message use for blind process
	* }
	*/
	std::string auth_key_str = mess["auth_key"];
	if (!bitmile::quickCompareStr(auth_key_str.c_str(), AUTH_KEY)) // <== not trust, dont continuous process
		return;

	std::string identify = mess["identify"];
	std::string data 	 = mess["data"];

	if (!identify.size())
		return;

	// TODO  something ->> start
	std::string signing_data = signingHandle.signingCaculator(data);
	// <<-- end
 
	// keep ip client with this signing data for each session
	std::pair<std::string, std::string> pair(identify, signing_data);

	// lock for insert new session
	{
		std::lock_guard<std::mutex> guard(mutex);
		signing_session.insert(pair);
	}
	// <<-- end
	
	// gen vote number for itself and add to map
	long long vote_num = bitmile::Peer::genVoteNumber();
	std::pair<std::string, long long> ip_vote(ip, vote_num);
	std::map<std::string, std::map<std::string, long long>>::iterator i = challenge_numbers.find(identify);
	if (i == challenge_numbers.end()){
		std::pair<std::string, std::map<std::string, long long>> pair_challenge(identify, std::map<std::string, long long>());
		pair_challenge.second.insert(ip_vote);
		challenge_numbers.insert(pair_challenge);
	}
	else {
		i->second.insert(ip_vote);
	}

send:
	// broadcat vote number to all node in network
	{
		/*
		* message format for response
		* {
		*  	"type": VOTE_MESSAGE
		*	"identify" : string <== continuous charactor have long length
		* 	"from_ip": string  
		*	"auth_key": string 	<== use for check is trust client
		* 	"vote" : string <== vote number use for compare 
		* }
		*/
		bitmile::Json mess_peer_request;
		mess_peer_request["type"] = mess_types[VOTE_MESSAGE];
		mess_peer_request["identify"] = mess["identify"];
		mess_peer_request["auth_key"] = AUTH_KEY;
		mess_peer_request["from_ip"] = ip;
		mess_peer_request["vote"] =  std::to_string(vote_num);
		broadcastMessage(mess_peer_request);
	}
}

void Peer::voteRequest(zmq::socket_t* socket_ptr,bitmile::Json& mess) {
	assert(socket_ptr);
	/*
	* message format for response
	* {
	*  	"type": VOTE_MESSAGE
	*	"identify" : string <== continuous charactor have long length
	* 	"from_ip": string  
	*	"auth_key": string 	<== use for check is trust client
	* 	"vote" : string <== vote number use for compare 
	* }
	*/
	std::string auth_key_str = mess["auth_key"];
	if (!bitmile::quickCompareStr(auth_key_str.c_str(), AUTH_KEY)) // <== not trust, dont continuous process
		return;

	std::string identify = mess["identity"];
	std::string from_ip = mess["from_ip"];
	
	long long vote_num;
	std::string vote_string = mess["vote"];
	sscanf(vote_string.c_str(), "%lld", &vote_num);
}

void Peer::inverseBlindNumberRequest(zmq::context_t* context_ptr, bitmile::Json& mess) {

}

long long Peer::genVoteNumber() {
	srand(time(NULL));
	return rand();
}
} // namespace bitmile