rm server-exe
g++ -g src/server/server.cpp -o server-exe  -Wall -I /opt/homebrew/opt/openssl@1.1/include -lcrypto
valgrind --tool=memcheck --leak-check=full ./server-exe 3000
