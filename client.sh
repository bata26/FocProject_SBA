rm client
g++ src/client/client.cpp -o client-exe -Wall -I /opt/homebrew/opt/openssl@1.1/include -lcrypto
./client-exe 3000
