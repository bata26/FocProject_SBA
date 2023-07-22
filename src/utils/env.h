//General
#define IV_LENGTH 16
#define HMAC_LENGTH 32
#define MAX_USERNAME_LENGTH 10
#define MIN_USERNAME_LENGTH 2
#define HMAC_KEY_SIZE 32
#define SERVER_IP "127.0.0.1"
#define BACKLOG_SIZE 5
#define BLOCK_SIZE 16
#define TRANSFERS_NUM 5
//Secure cin
#define USERNAME_WHITELIST_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"
#define OPERATION_WHITELIST_NUMS "1234"
#define TRANSFER_WHITELIST_NUMS "1234567890"
//Structures for network communication
#define HELLO 1
//Operations
#define BALANCE 1
#define TRANSFER 2
#define HISTORY 3
#define LOGOUT 4

#define SERVER_KEY_PWD "server"

// base path
#define BASE_CLIENT_PATH "./src/client/"
#define BASE_SERVER_PATH "./src/server/"