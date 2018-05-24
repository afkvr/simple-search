# simple-search
Modules for data search, using a simple scheme.

Menu

I. Dependencies

II. File server
  a. Dependecies
  b. Installation
  c. run instruction

III. Enterprise app
  a. Dependencies
  b. Installation
  c. run instruction

------------------------------------
project file hierachies:

   simple-search/
      -- blockchain/     /* helper class for blockchain interaction */
      -- database/       /* Deal's data inteface */
      -- message/        /* Messages' format exchanged between fileserver and enterprise app */
      -- utils/          /* helpers class to convert data from and to base64, hex form */
      -- vendors/        /* third parties libraries */ 
      -- file_server     /* specific code for file server */
	--inc/           /* file server code headers */
        --src/           /* file server code source */
        --tools/         /* helpers program */
       	  --dump_client/ /* simple client for file server */
	  --keygen/      /* program to generate public - secret keypair for tls */
      -- enterprise/	 /* specific code for enterprise app - QT project */


**** Note: prebuilt dependencies is here:
		+ https://drive.google.com/open?id=1t5CWfPSP2_1Ap0sU8d2g8w_5I7sU7SwF
		+ download and extract to simple-search/ 
			
--------------------------------------
I. Common Dependencies

   Install to system folder

   	- zmq 4.2.3: http://zeromq.org/intro:get-the-software
   	- zmq c++ binding: https://github.com/zeromq/cppzmq
   	- libsodium 1.0.16: https://github.com/jedisct1/libsodium/releases
	- Boost system, filesystem

   Install to simple-search/vendors/ folder
   	
	Move to simple-search/vendors/ folder:
	   
 	  cd simple-search/vendors

	- nlohmann json: 
		+ clone https://github.com/nlohmann/json
		+ build 
		+ create folders nlohmann_json/nlohmann in vendors
		+ copy json.hpp to nlohman_json/nlohmann
	- cpp-elasticsearch: 
		+ clone https://github.com/BitMile/cpp-elasticsearch
		
   	- openssl 1.0.2n: https://github.com/openssl/openssl
		+ down and build version 1.0.2n
		+ create folder openssl_1.0.2n
		+ copy include/openssl from openssl folder to openssl_1.0.2n
		+ create folder openssl_1.0.2n/lib/
		+ copy libcrypto.a, libssl.a to lib/

----------------------------------------

II. File server

a. Dependencies:
   - pthread
   
b. Installation

   cd simple-search
   cmake -H. -Bbuilds

c. Running
      
 
   Assume: an elasticsearch instance is running on port 9200


   cd build/file_server

   First time running:
	+ create data/ folder
        
	+ go to tools/keygen run keygen
	+ copy public_key.key and secret_key.key to build/file_server
   
   file server is ready, run it
   ./file_server
	
------------------------------------------

III. Enterprise app

a. Dependencies
   - Qt 9
   
   Important: All below lib are built based on opensll_1.0.2n: 
   - libcurl 7.59.0
   - curlcpp 
   - cryptopp700
   - socket.io 

   See prebuilt dependencies folder for file structure (or qmake file)


b. Installation
   
   - cd simple-search/enterprise/enterprise/
   - open enterprise.pro
   - build

c. Running
   
   First time:
	- copy public_key.key from II.c to build directory
        - rename it to server_public_key.key

   Run app



