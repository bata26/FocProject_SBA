rm client
g++ src/client/client.cpp -o client -Wall -I /opt/homebrew/opt/openssl@1.1/include -lcrypto
./client 3000
