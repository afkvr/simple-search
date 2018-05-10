#include "peer.hpp"
#include "utils.hpp"

// for rand number
#include <limits>
#include <random>
#include <cstdlib>

#define  inproc(name) "inproc://" name

namespace bitmile {
Peer::Peer () {
	setupFirst.store(false, std::memory_order_release);
	is_Proxy.store(false, std::memory_order_release);
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
 * @param bitmile::JsonHandle [ip1, ip2, ip3, ip4, ...]
 */
void Peer::syncPeerListRequest (zmq::context_t* context_ptr, bitmile::JsonHandle& ips) {
	assert(context_ptr);

	/*
	* message format for sync request
	* {
	*  	"type": SYNC_PEER_LIST
	*	"auth_key": string 	<== use for check is trust mode
	*   "peer_list": []		<== list ip
	* }
	*/
	bitmile::JsonHandle mess_sync;
	mess_sync["type"] 		= std::to_string(SYNC_PEER_LIST);
	mess_sync["auth_key"] 	= AUTH_KEY;
	mess_sync["peer_list"]  = ips;

	broadcastMessage(mess_sync);
}

void Peer::syncPeerListResponse (zmq::socket_t* socket_ptr, bitmile::JsonHandle& messJson) {
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
	for (bitmile::JsonHandle::iterator i = messJson["peer_list"].begin(); i != messJson["peer_list"].end(); i++) {
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
	bitmile::JsonHandle mess_request;
	mess_request[MESSAGE_KEY_TYPE] = std::to_string(GET_PEER_LIST);
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

void Peer::getPeerListResponse(zmq::socket_t* socket_ptr, bitmile::JsonHandle& mess) {
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

	bitmile::JsonHandle mess_response;

	bool is_exists = false; // <== check ip was exists in list ips
	bitmile::JsonHandle array = {};

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
			peer->setupFirst.store(true, std::memory_order_release);
			peer->is_Proxy.store(true, std::memory_order_release);
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
		try {
			zmq::message_t request;
			rep_socket.recv(&request);
			std::cout << "have message " << std::endl;

			// convert request data to json
			bitmile::JsonHandle mess((char*)(request.data()));

			// notify sync peer list from other node
			int mess_type = mess.getType();

			if (mess_type == GET_PEER_LIST) {
				peer->getPeerListResponse (&rep_socket, mess);
			}

			else if (mess_type == SYNC_PEER_LIST) {
				peer->syncPeerListResponse(&rep_socket, mess);
			}

			// request for new vote, find one in group will use for decrypt process
			else if (mess_type == VOTE_MESSAGE) {
				peer->voteRequest(&rep_socket, mess);
			}

			// request signing message from client app
			else if (mess_type == CLIENT_SIGNING_MESSAGE) {
				peer->clientSigningMessageReq(&rep_socket, mess);
			}

			// request signing message from peer node in network
			else if (mess_type == PEER_SIGNING_MESSAGE) {
				peer->peerSigningMessageReq(&rep_socket, mess);
			}

			// caculate signature with winner in network after vote
			else if (mess_type == CACULATE_SIGNATURE_MESSAGE) {
				peer->caculateSignatureMessageRequest(&rep_socket, mess);
			}
		} catch (std::exception& e) {
			std::cout << "have error " << e.what() << std::endl;
		}

		zmq::message_t reponse(1);
		rep_socket.send(reponse);
	}
}

# define END_CHARATOR '\0'
void Peer::ssend (zmq::socket_t* socket_ptr, std::string& data) {
	long long mess_real_size = data.size()+1; // <== one byte for end charator
	zmq::message_t mess(mess_real_size);
	memcpy(mess.data(), data.c_str(), data.size());

	// set end charator for string
	char* char_ptr = (char*)mess.data();
	char_ptr[data.size()] = END_CHARATOR;

	socket_ptr->send(mess);
}

std::string Peer::concatTcpIp(const char* ip, const char* port) {
	return std::string("tcp://") + ip + std::string(":") + std::string(port);
}

void Peer::caculateSignatureMessageRequest(zmq::socket_t* socket_ptr, bitmile::JsonHandle& mess) {
	std::cout << "Peer::caculateSignatureMessageRequest start " << mess.dump() << std::endl;
	assert(socket_ptr);

	// not continuous if itself is proxy
	if (is_Proxy.load(std::memory_order_acquire)) {
		return;
	}

	/*
	* message format for response
	* {
	*  	"type": CACULATE_SIGNATURE_MESSAGE
	*	"identify" : string <== continuous charactor have long length
	* 	"from_ip": string  
	*	"auth_key": string 	<== use for check is trust client
	* 	"data" : string <== vote number use for compare
	*	"callback_ip" : string <== ip of client
	* }
	*/
	std::string auth_key_str = mess["auth_key"];

	// if not trust, dont continuous process
	if (!bitmile::quickCompareStr(auth_key_str.c_str(), AUTH_KEY))
		return;

	std::string identify = mess["identify"];
	std::string data 	 = mess["data"];

	if (!identify.size())
		return;

	std::map<std::string, std::list<std::string>>::iterator i = signature_data_session.find(identify);

	// if pair of identify not exists before
	if (i == signature_data_session.end()) {
		std::pair<std::string, std::list<std::string>> pair(identify, std::list<std::string>());
		pair.second.push_back(data);
		signature_data_session.insert(pair);
	}
	else {
		i->second.push_back(data);
	}

	// get again
	i = signature_data_session.find(identify);

	// if num of partial signature data from other node in network not equal size with size of peer list
	// dont continous process
	if (i->second.size() < peer_ips.size()) 
		return;

	// caculate signature message and send to generator_server
	{

		// send signature data to generator node
		/*
		* message format for response
		* {
		*  	"type": INVERSE_BLIND_MESSAGE
		*	"identify" : string <== continuous charactor have long length
		*	"auth_key": string 	<== use for check is trust client
		* 	"data" : string  	<== signature data
		*	"callback_ip" : string <== ip of client
		* }
		*/
		bitmile::JsonHandle inverse_mess_req;
		inverse_mess_req["type"] = std::to_string(INVERSE_BLIND_MESSAGE);
		inverse_mess_req["identify"] = identify;
		inverse_mess_req["auth_key"] = AUTH_KEY;
		inverse_mess_req["data"] = mess["data"]; // <== fake, need change to caculated value in future
		inverse_mess_req["callback_ip"] = mess["callback_ip"];

		// create empty blind_server_ips for
		bitmile::JsonHandle blind_server_ips = {};
		inverse_mess_req["blind_server_ips"] = blind_server_ips;
		
		{
			// caculate signing message at here 
		}

		// send to generator server group		
		std::string mess_dump = inverse_mess_req.dump();
		zmq::context_t context(1);
		zmq::socket_t socket(context, ZMQ_REQ);

		std::cout << "Peer::caculateSignatureMessageRequest send to signature server " << mess_dump << std::endl;
		std::cout << "generator server  " << bitmile::Peer::concatTcpIp(GENERATOR_BOSS_IP, GENERATOR_BOSS_PORT).c_str() << std::endl;
		
		// connect to generator boss 
		socket.connect(bitmile::Peer::concatTcpIp(GENERATOR_BOSS_IP, GENERATOR_BOSS_PORT).c_str());
		ssend(&socket, mess_dump); // <== fake

		std::cout << "signature_data_session list size before " << signature_data_session.size() << std::endl;

		// clear session
		signature_data_session.erase(identify);

		std::cout << "signature_data_session list size after " << signature_data_session.size() << std::endl;
	}
}

/*
 * Generate blind message from random blind number
 */
void Peer::clientSigningMessageReq(zmq::socket_t* socket_ptr, bitmile::JsonHandle& mess) {
	std::cout << "Peer::clientSigningMessageReq start" << mess.dump() << std::endl;
	assert(socket_ptr);

	/*
	* message format for recv
	* {
	*  	"type": CLIENT_SIGNING_MESSAGE
	*	"identify": string  <== continuous charactor have long length
	* 	"callback_ip": string  <== after signing process successful, send signing data back to callback_ip 
	*	"auth_key": string 	<== use for check is trust client
	*	"data": string 	<== message use for blind process
	* }
	*/
	std::string auth_key_str = mess["auth_key"];

	// if not trust, dont continuous process
	if (!bitmile::quickCompareStr(auth_key_str.c_str(), AUTH_CLIENT_KEY))
		return;

	std::string identify = mess["identify"];
	std::string data 	 = mess["data"];

	if (!identify.size())
		return;

	// gen partial of signing data if this is client node
	if (!is_Proxy.load(std::memory_order_acquire)) {
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
	}


 	// notify to other node in network for create singing data 
	{
		bitmile::JsonHandle mess_peer_request;

		/*
		* message format for response
		* {
		*  	"type": PEER_SIGNING_MESSAGE
		* 	"identify": string  <== continuous charactor have long length  
		*	"auth_key": string 	<== use for check is trust client
		* 	"callback_ip": string  <== after signing process successful, send signing data back to callback_ip 
		*	"data": string 	<== message use for blind process
		* }
		*/
		mess_peer_request["type"] = std::to_string(PEER_SIGNING_MESSAGE);
		mess_peer_request["identify"] = mess["identify"];
		mess_peer_request["auth_key"] = AUTH_KEY;
		mess_peer_request["callback_ip"] = mess["callback_ip"];
		mess_peer_request["data"] = mess["data"]; // fake, need change in future, after add logic for interact with mess data
		broadcastMessage(mess_peer_request);
	}

	// gen vote number for itself, just for client node
	long long vote_num;
	if (!is_Proxy.load(std::memory_order_acquire)) {
		vote_num = bitmile::Peer::genVoteNumber();
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
		*	"callback_ip": string
		* 	"vote" : string <== vote number use for compare 
		* }
		*/
		bitmile::JsonHandle mess_peer_request;
		mess_peer_request["type"] = std::to_string(VOTE_MESSAGE);
		mess_peer_request["identify"] = mess["identify"];
		mess_peer_request["auth_key"] = AUTH_KEY;
		mess_peer_request["from_ip"] = ip;
		mess_peer_request["callback_ip"] = mess["callback_ip"];
		
		if (!is_Proxy.load(std::memory_order_acquire))
			mess_peer_request["vote"] =  std::to_string(vote_num);
		
		broadcastMessage(mess_peer_request);
	}
}

void Peer::broadcastMessage(bitmile::JsonHandle& mess) {
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
	}
}

/*
 *  Request signing message from other peer
 */
void Peer::peerSigningMessageReq(zmq::socket_t* socket_ptr,bitmile::JsonHandle& mess) {
	std::cout << "Peer::peerSigningMessageReq start " << mess.dump() << std::endl;

	assert(socket_ptr);

	// not continuous if itself is proxy
	if (is_Proxy.load(std::memory_order_acquire)) {
		return;
	}

	/*
	* message format for response
	* {
	*  	"type": PEER_SIGNING_MESSAGE
	* 	"identify": string  <== continuous charactor have long length  
	*	"auth_key": string 	<== use for check is trust client
	* 	"callback_ip": string  <== after signing process successful, send signing data back to callback_ip 
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
		*	"callback_ip": string 
		* }
		*/
		bitmile::JsonHandle mess_peer_request;
		mess_peer_request["type"] = std::to_string(VOTE_MESSAGE);
		mess_peer_request["identify"] = mess["identify"];
		mess_peer_request["auth_key"] = AUTH_KEY;
		mess_peer_request["from_ip"] = ip;
		mess_peer_request["vote"] =  std::to_string(vote_num);
		mess_peer_request["callback_ip"] = mess["callback_ip"];
		broadcastMessage(mess_peer_request);

		std::cout << "Peer::peerSigningMessageReq size of signing_session " <<  signing_session.size() << std::endl;
		std::cout << "Peer::peerSigningMessageReq size of challenge_numbers with identify " 
		<< identify << " is " << challenge_numbers.find(identify)->second.size() << std::endl;
	}
}

// need more process
void Peer::voteRequest(zmq::socket_t* socket_ptr,bitmile::JsonHandle& mess) {
	std::cout << "Peer::voteRequest start " << mess.dump() << std::endl;
	assert(socket_ptr);

	// dont continuous if itself is Proxy
	if (is_Proxy.load(std::memory_order_acquire))
		return;
	
	/*
	* message format for response
	* {
	*  	"type": VOTE_MESSAGE
	*	"identify" : string <== continuous charactor have long length
	* 	"from_ip": string  
	*	"auth_key": string 	<== use for check is trust client
	*	"callback_ip": string
	* 	"vote" : string <== vote number use for compare 
	* }
	*/
	std::string auth_key_str = mess["auth_key"];
	if (!bitmile::quickCompareStr(auth_key_str.c_str(), AUTH_KEY)) // <== not trust, dont continuous process
		return;

	std::string identify = mess["identify"];
	std::string from_ip = mess["from_ip"];

	// get entry point of challenge number list
	std::map<std::string, std::map<std::string, long long>>::iterator i = challenge_numbers.find(identify);

	// dont assign vote number  if from_ip is boss ip
	if (!bitmile::quickCompareStr(from_ip.c_str(), BOSS_IP)) {
		std::cout << "Peer::voteRequest not is proxy  " << std::endl;
		std::string vote_string = mess["vote"];
		long long vote_num = std::stoll(vote_string);
		std::cout << "Peer::voteRequest vote num  " << vote_num << std::endl;

		// add vote number to map
		std::pair<std::string, long long> ip_vote(from_ip, vote_num);
		if (i == challenge_numbers.end()){
			std::pair<std::string, std::map<std::string, long long>> pair_challenge(identify, std::map<std::string, long long>());
			pair_challenge.second.insert(ip_vote);
			challenge_numbers.insert(pair_challenge);
		}
		else {
			i->second.insert(ip_vote);
		}
	}

	// refind again, if still dont exists in session list , return
	if (i == challenge_numbers.end() && (i = challenge_numbers.find(identify)) == challenge_numbers.end()) {
		return;
	}

	std::cout << "Peer::voteRequest vote list size " << i->second.size() << std::endl;

	//dont process if list size of  challenge  number less than num of peer ips in network
	if (i->second.size() != peer_ips.size())
		return;

	// find winner
	std::map<std::string, long long>::iterator winner = i->second.begin();
	for (std::map<std::string, long long>::iterator j =  ++i->second.begin(); j != i->second.end(); j++) {
		std::cout << "Peer::voteRequest loop " << j->second << " and winner " << winner->second << std::endl;

		if (winner->second < j->second)
			winner = j;
	}

	std::cout << "Peer::voteRequest winner " << winner->first << " with value " << winner->second << std::endl;

	// if winner is itself , dont continous process
	bool is_winner = bitmile::quickCompareStr(ip.c_str(),winner->first.c_str());

	// send signature data to win node (have biggest number)
	/*
	* message format for response
	* {
	*  	"type": CACULATE_SIGNATURE_MESSAGE
	*	"identify" : string <== continuous charactor have long length
	* 	"from_ip": string  
	*	"auth_key": string 	<== use for check is trust client
	* 	"data" : string <== vote number use for compare
	*	"callback_ip" : string <== ip of client
	* }
	*/
	std::map<std::string, std::string>::iterator partial_signature_data = signing_session.find(identify);
	if (partial_signature_data != signing_session.end()) 
 	{
 		bitmile::JsonHandle signature_data;
		signature_data["type"] = std::to_string(CACULATE_SIGNATURE_MESSAGE);
		signature_data["identify"] = identify;
		signature_data["from_ip"] = ip;
		signature_data["auth_key"] = AUTH_KEY;
		signature_data["data"] =  partial_signature_data->second;
		signature_data["callback_ip"] = mess["callback_ip"];

 		if (!is_winner) {
			zmq::context_t context(1);
			zmq::socket_t socket(context, ZMQ_REQ);
			std::cout << "caculate signature data " << bitmile::Peer::concatTcpIp(winner->first.c_str(),PORT_) << std::endl;
			socket.connect(bitmile::Peer::concatTcpIp(winner->first.c_str(),PORT_).c_str());
			std::string dump_mess = signature_data.dump();
			ssend(&socket, dump_mess);
			socket.close();
		}
		// send signature mesage back to itself if this is winner
		else {
			caculateSignatureMessageRequest(socket_ptr, signature_data);
		} 
	}

	challenge_numbers.erase(identify);
	signing_session.erase(identify);
}

long long Peer::genVoteNumber() {
	std::random_device rd;

	std::default_random_engine e1(rd());
	std::uniform_int_distribution<long long> distribution(1, std::numeric_limits<long long>::max());

	long long random_val = distribution(e1);
	std::cout << "Peer::genVoteNumber " << random_val << std::endl;
	return random_val;
}
} // namespace bitmile