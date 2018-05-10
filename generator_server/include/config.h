
#ifndef _CONFIG_HPP_INCLUDED_
#define _CONFIG_HPP_INCLUDED_
/*
 * config file
 * setup values for common variables 
 */
#define WORKER_THREAD_ 5
#define PORT_	"6666" 

/* briged for inter process communication */
#define DEALER_NAME_ "dealer"

/*
 * BOSS IP of group peer machine
 * will change in future
 */
#define BOSS_IP "192.168.1.70" //<== fake, need chaged if run on other machine because is local ip


/*
 * FILE SERVER ip
 */
#define FILE_SERVER_IP "192.168.1.70" // <== fake, need chaged if run on other machine because is local ip

/*
 * FILE SERVER port
 */
#define FILE_SERVER_PORT "7777" // <== fake


/*
 * Boss ip of instance in signing Server
 * will change in future
 */
#define SIGNING_BOSS_IP "192.168.1.70" // <== fake, need chaged if run on other machine because is local ip

/*
 * Key for auth friend server
 * Use open ssl for establis connection
 */
#define AUTH_KEY "generator_server"	// <== fake, should change to random charater have long length (512 or 1024 or 2048 bit) ? 
#define AUTH_CLIENT_KEY "auth_client" 	// <== fake, should change to random charater have long length (512 or 1024 or 2048 bit) ? 
#define AUTH_SINGING_SERVER "signing_server" // <== fake, should change to random charater have long length (512 or 1024 or 2048 bit) ? 

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
	
	CLIENT_BLIND_NUMBER_REQUEST,
	CLIENT_BLIND_NUMBER_RESPONSE,

	PEER_BLIND_NUMBER_REQUEST,
	PEER_BLIND_NUMBER_RESPONSE,
	
	BLIND_MESSAGE,
	INVERSE_BLIND_MESSAGE,

	// just for Proxy
	UPLOAD_DOC_REQUEST
};

}
#endif
