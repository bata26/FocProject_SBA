rm server
g++ src/server/server.cpp -o server -Wall -I /opt/homebrew/opt/openssl@1.1/include -lcrypto
./server 3000
