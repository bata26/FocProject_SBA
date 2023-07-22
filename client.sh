rm client-exe
g++ -w src/client/client.cpp -o client-exe -Wall -I /opt/homebrew/opt/openssl@1.1/include -lcrypto
./client-exe 3000
