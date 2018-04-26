rm test
g++ -std=c++11 -o test src/peer.cpp -pthread -lzmq main.cpp
