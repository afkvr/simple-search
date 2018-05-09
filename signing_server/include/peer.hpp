#ifndef _PEER_HPP_INCLUDED_
#define _PEER_HPP_INCLUDED_

#include <iostream>
#include <queue>
#include <thread>
#include <zmq.hpp>
#include <list>
#include <mutex>
#include <atomic>

#include "config.h"
#include "jsonhandle.hpp"
#include "signinghandle.hpp"

namespace bitmile {
class Peer {
	public:
		Peer();
		~Peer();

		bool run();
	private:
		bool setupWorker(zmq::context_t*);
		std::string getPublicIp();

		/*
		 * Because we use P2P comunication, so we need keep all node ip  in network
		 */
		void syncPeerListRequest (zmq::context_t*, bitmile::JsonHandle&);
		void syncPeerListResponse (zmq::socket_t*, bitmile::JsonHandle&);
		
		/* 
		 * For new instance join to network
		 * it need notify itself to boss instance
		 * network will keep ip to common list then notify to all node in network
		 */
		void notifyConnection (zmq::context_t*);
		void getPeerListResponse(zmq::socket_t*, bitmile::JsonHandle&);


		/*
		 * handle request from client app
		 */
		void clientSigningMessageReq(zmq::socket_t* socket_ptr, bitmile::JsonHandle& mess);
		
		/*
		 * request other peer signing message
		 */
		void peerSigningMessageReq(zmq::socket_t*,bitmile::JsonHandle&);

		/*
		 * Vote instance will use for caculate private key
		 * logic: 
		 * 	1. generate random number
		 * 	2. broacast to other instances in network
		 * 	3. if random number of instance is biggest, then use for caculate process
		 * <-- this logic will change in future
		 */
		void voteRequest(zmq::socket_t*,bitmile::JsonHandle&);

		/*
		 * caculate signature from all peer in network
		 * process happen in winner node after vote challange
		 */
		void caculateSignatureMessageRequest(zmq::socket_t*, bitmile::JsonHandle&);

		// broadcast message
		void broadcastMessage(bitmile::JsonHandle&);

		// utils
		static inline void handleMessage(Peer*, worker_t*, zmq::context_t*);
		static inline std::string concatTcpIp(const char* ip, const char* port);
		static inline void ssend (zmq::socket_t*, std::string&);
		static inline long long genVoteNumber();
	private:
		//std::queue<long long> thread_ids;
		std::queue<worker_t*> worker_list;

		// keep ips of peer node machine in network;
		// address value was string
		std::list<std::string> peer_ips;

		// keep mapper between app client identify and signing data
		// pair {identify : signing_data}
		std::map<std::string, std::string> signing_session;

		// keep mapper betweeb app client identify and partial signature data
		// signature data will be remove when caculate successful and send to genarator sever group
		// pair {identify : list_partial_signature_data}
		std::map<std::string, std::list<std::string>> signature_data_session;

		// keep flag check peer node was setup before run
		std::atomic<bool> setupFirst;
		
		std::string ip;
		std::mutex mutex;

		bitmile::SigningHandle signingHandle;

		/* 
		 * keep mapper between app client identify and list challenge number for each session
		 * pair {identify : [{peer_ip, vote_number}, ...]}
		 */
		std::map<std::string, std::map<std::string, long long>> challenge_numbers;

		std::atomic<bool> is_Proxy;
	};
}

#endif