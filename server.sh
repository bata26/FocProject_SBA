rm server
g++ src/server/server.cpp -o server-exe -Wall -I /opt/homebrew/opt/openssl@1.1/include -lcrypto
./server-exe 3000
