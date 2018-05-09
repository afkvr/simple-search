
#ifndef _CONFIG_HPP_INCLUDED_
#define _CONFIG_HPP_INCLUDED_
/*
 * config file
 * setup values for common variables 
 */
#define WORKER_THREAD_ 5
#define PORT_	"5555"

/* briged for inter process communication */
#define DEALER_NAME_ "dealer"

/*
 * BOSS IP of group peer machine
 */
#define BOSS_IP "192.168.1.70" // <== fake

/*
 * Boss ip of instance in generater Server
 */
#define GENERATOR_BOSS_IP "192.168.1.70" // <-- fake
#define GENERATOR_BOSS_PORT "6666"

/*
 * Key for auth friend server
 * Use open ssl for establis connection
 */
#define AUTH_KEY "signing_server"	// <== fake, should change to random charater have long length (512 or 1024 or 2048 bit) ? 
#define AUTH_CLIENT_KEY "auth_client" 	// <== fake, should change to random charater have long length (512 or 1024 or 2048 bit) ? 
#define AUTH_GENERATE_SERVER "auth_generate_server" // <== fake, should change to random charater have long length (512 or 1024 or 2048 bit) ? 
/*
 * defined unknow number
 */
#define UNKNOW_NUM "NaN"

#define MODULO_NUM "13"  // <== fake, should change in future

namespace bitmile {
/* define common type */
enum worker_type_ {
	ROUTER=0,
	DEALER=1,
	HANDLE_MESS=2
};

struct worker_t {
	worker_type_ type;
	long long id;
	void* thread_ptr = 0;
	bool isWorking = false;
};

enum MESS_TYPE {
	GET_PEER_LIST = 0,
	SYNC_PEER_LIST,
	VOTE_MESSAGE,
	CLIENT_SIGNING_MESSAGE,
	PEER_SIGNING_MESSAGE,
	NOTYFY_CONNECTION,
	CACULATE_SIGNATURE_MESSAGE,

	// For generator server
	INVERSE_BLIND_MESSAGE
};

}
#endif
