rm client-exe
g++ -g src/client/client.cpp -o client-exe  -Wall -I /opt/homebrew/opt/openssl@1.1/include -lcrypto 
valgrind --tool=memcheck --leak-check=full ./client-exe 3000
