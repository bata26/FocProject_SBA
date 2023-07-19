#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <limits.h>
#include <fstream>
#include <vector>
#include <string>
#include <limits>
#include <string.h>
#include <math.h>
#include <dirent.h>
#include <iostream>
#include <string.h>
#include "env.h"
#include "cryptoFunctions.cpp"

using namespace std;


struct helloPkt
{
    uint16_t code = HELLO;
    uint16_t usernameLen;
    string username;
    uint32_t symmetricKeyLen;
    uint32_t hmacKeyLen;
    EVP_PKEY* clientSymmKeyParam = nullptr;
    EVP_PKEY* clientHmacKeyParam = nullptr;

    //Serialize the message to send it through the network
    void* serializeMessage(int &len)
    {
        uint8_t* serializedPkt = nullptr;
        int pointer = 0;

        void* bufferSymmetricKey = nullptr;
        void* bufferHmacKey = nullptr;   

        // Serializes key to send it throught the network using BIO structure
        bufferSymmetricKey = serializeKey(clientSymmKeyParam, symmetricKeyLen);
        if (bufferSymmetricKey == nullptr)
        {
            return nullptr;
        }

        // Serializes key to send it throught the network using BIO structure
        bufferHmacKey = serializeKey(clientHmacKeyParam, hmacKeyLen);
        if (bufferHmacKey == nullptr)
        {
            return nullptr;
        }

        uint16_t certified_code = htons(code);
        usernameLen = username.length();
        uint16_t certified_username_len = htons(usernameLen);

        // Total length of the serialized packet
        len = sizeof(certified_code) + sizeof(certified_username_len) + usernameLen + sizeof(symmetricKeyLen) + sizeof(hmacKeyLen) + symmetricKeyLen + hmacKeyLen;
        serializedPkt = (uint8_t *)malloc(len);
        if (!serializedPkt)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            return nullptr;
        }

        // Copy of the code
        memcpy(serializedPkt, &certified_code, sizeof(certified_code));
        pointer += sizeof(code);

        // Copy username_len
        memcpy(serializedPkt + pointer, &certified_username_len, sizeof(certified_username_len));
        pointer += sizeof(usernameLen);

        // Copy of the username
        uint8_t* username_certified = (uint8_t *)username.c_str();
        memcpy(serializedPkt + pointer, username_certified, usernameLen);
        pointer += usernameLen;

        // Copy of symmetric_key_param_len
        uint32_t certified_symmetric_len = htonl(symmetricKeyLen);
        memcpy(serializedPkt + pointer, &certified_symmetric_len, sizeof(certified_symmetric_len));
        pointer += sizeof(certified_symmetric_len);

        // Copy of hmac_key_param_len
        uint32_t certified_hmac_len = htonl(hmacKeyLen);
        memcpy(serializedPkt + pointer, &certified_hmac_len, sizeof(certified_hmac_len));
        pointer += sizeof(certified_hmac_len);

        // Copy of the symmetric_key_param buffer
        memcpy(serializedPkt + pointer, bufferSymmetricKey, symmetricKeyLen);
        pointer += symmetricKeyLen;

        // Copy of the hmac_key_param buffer
        memcpy(serializedPkt + pointer, bufferHmacKey, hmacKeyLen);

        free(bufferSymmetricKey);
        free(bufferHmacKey);

        return serializedPkt;
    }

    //Deserializes a message received from the network
    bool deserializeMessage(uint8_t* serializedPkt)
    {
        uint64_t pointer = 0;

        // Copy of the code
        memcpy(&code, serializedPkt, sizeof(code));
        code = ntohs(code);

        if (pointer > numeric_limits<uint64_t>::max() - sizeof(code))
        {
            return false;
        }
        pointer += sizeof(code);

        //Checks code of the packet
        if (code != HELLO)
        {
            cerr << "[ERROR] invalid packet code!" << endl;
            return false;
        }

        // Copy username_len
        memcpy(&usernameLen, serializedPkt + pointer, sizeof(usernameLen));
        usernameLen = ntohs(usernameLen);
        if (pointer > numeric_limits<uint64_t>::max() - sizeof(usernameLen))
        {
            return false;
        }
        pointer += sizeof(usernameLen);

        // Copy username
        username.assign((char *)serializedPkt + pointer, usernameLen);
        if (pointer > numeric_limits<uint64_t>::max() - usernameLen)
        {
            return false;
        }
        pointer += usernameLen;

        // Copy of symmetric_key_param_len
        memcpy(&symmetricKeyLen, serializedPkt + pointer, sizeof(symmetricKeyLen));
        symmetricKeyLen = ntohl(symmetricKeyLen);
        if (pointer > numeric_limits<uint64_t>::max() - sizeof(symmetricKeyLen))
        {
            return false;
        }
        pointer += sizeof(symmetricKeyLen);

        // Copy of hmac_key_param_len
        memcpy(&hmacKeyLen, serializedPkt + pointer, sizeof(hmacKeyLen));
        hmacKeyLen = ntohl(hmacKeyLen);
        if (pointer > numeric_limits<uint64_t>::max() - sizeof(hmacKeyLen))
        {
            return false;
        }
        pointer += sizeof(hmacKeyLen);

        // Copy of the symmetric parameter
        clientSymmKeyParam = deserializeKey(serializedPkt + pointer, symmetricKeyLen);
        if (pointer > numeric_limits<uint64_t>::max() - symmetricKeyLen)
        {
            return false;
        }
        pointer += symmetricKeyLen;
        // Copy of the hmac parameter
        clientHmacKeyParam = deserializeKey(serializedPkt + pointer, hmacKeyLen);

        if (clientHmacKeyParam == nullptr || clientSymmKeyParam == nullptr)
        {
            cerr << "[ERROR] Couldn't deserialize correctly a key! " << endl;
            return false;
        }
        return true;
    }
};

struct login_authentication_pkt
{
    // Clear
    uint32_t serverSymmetricKeyParamClearLen = 0;
    uint32_t serverHmacKeyParamClearLen = 0;
    uint32_t encryptedSignLen = 0;
    uint8_t* iv = nullptr;
    EVP_PKEY* serverSymmetricKeyParamClear = nullptr;
    EVP_PKEY* serverHmacKeyParamClear = nullptr;

    //Encrypted sign
    uint8_t* encryptedSign = nullptr;

    // Encrypted signed part to be serialized
    uint32_t symmetric_key_param_len_server = 0;
    uint32_t hmac_key_param_len_server = 0;
    uint32_t symmetric_key_param_len_client = 0;
    uint32_t hmac_key_param_len_client = 0;

    EVP_PKEY* symmetric_key_param_server = nullptr;
    EVP_PKEY* hmac_key_param_server = nullptr;
    EVP_PKEY* symmetric_key_param_client = nullptr;
    EVP_PKEY* hmac_key_param_client = nullptr;

    void* serialize_part_to_encrypt(int &len)
    {
        int pointer_counter = 0;
        uint8_t* serialized_pte;

        // Evp serializations to pass data through the network
        void* key_buffer_symmetric_server = serializeKey(symmetric_key_param_server, symmetric_key_param_len_server);
        void* key_buffer_hmac_server = serializeKey(hmac_key_param_server, hmac_key_param_len_server);
        void* key_buffer_symmetric_client = serializeKey(symmetric_key_param_client, symmetric_key_param_len_client);
        void* key_buffer_hmac_client = serializeKey(hmac_key_param_client, hmac_key_param_len_client);

        // Total length
        len = sizeof(symmetric_key_param_len_server) + sizeof(hmac_key_param_len_server) + sizeof(symmetric_key_param_len_client) +
              sizeof(hmac_key_param_len_client) + symmetric_key_param_len_server + hmac_key_param_len_server + symmetric_key_param_len_client +
              hmac_key_param_len_client;

        serialized_pte = (uint8_t *)malloc(len);
        if (!serialized_pte)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            return nullptr;
        }

        // Get lengths of 4 keys
        uint32_t certified_symmetric_key_param_len_server = htonl(symmetric_key_param_len_server);
        uint32_t certified_hmac_key_param_len_server = htonl(hmac_key_param_len_server);
        uint32_t certified_symmetric_key_param_len_client = htonl(symmetric_key_param_len_client);
        uint32_t certified_hmac_key_param_len_client = htonl(hmac_key_param_len_client);

        // Start copying
        memcpy(serialized_pte + pointer_counter, &certified_symmetric_key_param_len_server, sizeof(certified_symmetric_key_param_len_server));
        pointer_counter += sizeof(certified_symmetric_key_param_len_server);
        memcpy(serialized_pte + pointer_counter, &certified_hmac_key_param_len_server, sizeof(certified_hmac_key_param_len_server));
        pointer_counter += sizeof(certified_hmac_key_param_len_server);
        memcpy(serialized_pte + pointer_counter, &certified_symmetric_key_param_len_client, sizeof(certified_symmetric_key_param_len_client));
        pointer_counter += sizeof(certified_symmetric_key_param_len_client);
        memcpy(serialized_pte + pointer_counter, &certified_hmac_key_param_len_client, sizeof(certified_hmac_key_param_len_client));
        pointer_counter += sizeof(certified_hmac_key_param_len_client);
        memcpy(serialized_pte + pointer_counter, key_buffer_symmetric_server, symmetric_key_param_len_server);
        pointer_counter += symmetric_key_param_len_server;
        memcpy(serialized_pte + pointer_counter, key_buffer_hmac_server, hmac_key_param_len_server);
        pointer_counter += hmac_key_param_len_server;
        memcpy(serialized_pte + pointer_counter, key_buffer_symmetric_client, symmetric_key_param_len_client);
        pointer_counter += symmetric_key_param_len_client;
        memcpy(serialized_pte + pointer_counter, key_buffer_hmac_client, hmac_key_param_len_client);
        pointer_counter += hmac_key_param_len_client;

        // Frees
        free(key_buffer_symmetric_server);
        free(key_buffer_hmac_server);
        free(key_buffer_symmetric_client);
        free(key_buffer_hmac_client);

        return serialized_pte;
    }

    void* serialize_message(int &len)
    {
        int pointer_counter = 0;
        uint8_t* serialized_pkt;
        void* key_buffer_symmetric_server_clear = nullptr;
        void* key_buffer_hmac_server_clear = nullptr;

        if (encryptedSign == nullptr || encryptedSignLen == 0 || iv == nullptr)
        {
            cerr << "[ERROR] Missing field!" << endl;
            return nullptr;
        }

        // Symm_key
        key_buffer_symmetric_server_clear = serializeKey(serverSymmetricKeyParamClear, serverSymmetricKeyParamClearLen);
        uint32_t certified_symmetric_key_server_clear_len = htonl(serverSymmetricKeyParamClearLen);

        // Hmac_key
        key_buffer_hmac_server_clear = serializeKey(serverHmacKeyParamClear, serverHmacKeyParamClearLen);
        uint32_t certified_hmac_key_server_clear_len = htonl(serverHmacKeyParamClearLen);

        uint32_t certified_encrypted_signing_len = htonl(encryptedSignLen);

        //Total len
        len = sizeof(certified_symmetric_key_server_clear_len) + sizeof(certified_hmac_key_server_clear_len) + sizeof(certified_encrypted_signing_len) + IV_LENGTH + serverSymmetricKeyParamClearLen + serverHmacKeyParamClearLen + encryptedSignLen;

        serialized_pkt = (uint8_t *)malloc(len);
        if (!serialized_pkt)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            return nullptr;
        }

        // Start copying
        memcpy(serialized_pkt, &certified_symmetric_key_server_clear_len, sizeof(certified_symmetric_key_server_clear_len));
        pointer_counter += sizeof(certified_symmetric_key_server_clear_len);
        memcpy(serialized_pkt + pointer_counter, &certified_hmac_key_server_clear_len, sizeof(certified_hmac_key_server_clear_len));
        pointer_counter += sizeof(certified_hmac_key_server_clear_len);
        memcpy(serialized_pkt + pointer_counter, &certified_encrypted_signing_len, sizeof(certified_encrypted_signing_len));
        pointer_counter += sizeof(encryptedSignLen);
        memcpy(serialized_pkt + pointer_counter, iv, IV_LENGTH);
        pointer_counter += IV_LENGTH;
        memcpy(serialized_pkt + pointer_counter, key_buffer_symmetric_server_clear, serverSymmetricKeyParamClearLen);
        pointer_counter += serverSymmetricKeyParamClearLen;
        memcpy(serialized_pkt + pointer_counter, key_buffer_hmac_server_clear, serverHmacKeyParamClearLen);
        pointer_counter += serverHmacKeyParamClearLen;
        memcpy(serialized_pkt + pointer_counter, encryptedSign, encryptedSignLen);

        // Frees
        free(key_buffer_symmetric_server_clear);
        free(key_buffer_hmac_server_clear);
        return serialized_pkt;
    }

    void* serialize_message_no_clear_keys(int &len)
    {
        int pointer_counter = 0;
        uint8_t* serialized_pkt;

        if (encryptedSign == nullptr || encryptedSignLen == 0 || iv == nullptr)
        {
            cerr << "[ERROR] Missing field!" << endl;
            return nullptr;
        }

        uint32_t certified_encrypted_signing_len = htonl(encryptedSignLen);

        //Total len
        len = sizeof(certified_encrypted_signing_len) + IV_LENGTH +  encryptedSignLen;

        serialized_pkt = (uint8_t *)malloc(len);
        if (!serialized_pkt)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            return nullptr;
        }

        // Start copying
        memcpy(serialized_pkt + pointer_counter, &certified_encrypted_signing_len, sizeof(certified_encrypted_signing_len));
        pointer_counter += sizeof(encryptedSignLen);
        memcpy(serialized_pkt + pointer_counter, iv, IV_LENGTH);
        pointer_counter += IV_LENGTH;
        memcpy(serialized_pkt + pointer_counter, encryptedSign, encryptedSignLen);

        return serialized_pkt;
    }

    bool deserialize_message(uint8_t* serialized_pkt_received)
    {
        uint64_t pointer_counter = 0;

        if (iv != nullptr)
        {
            iv = nullptr;
        }

        // From the serialized_pkt_received we get all the lengths and then the keys
        memcpy(&serverSymmetricKeyParamClearLen, serialized_pkt_received + pointer_counter, sizeof(serverSymmetricKeyParamClearLen));
        serverSymmetricKeyParamClearLen = ntohl(serverSymmetricKeyParamClearLen);
        if (pointer_counter > numeric_limits<uint64_t>::max() - sizeof(serverSymmetricKeyParamClearLen))
        {
            return false;
        }
        pointer_counter += sizeof(serverSymmetricKeyParamClearLen);

        memcpy(&serverHmacKeyParamClearLen, serialized_pkt_received + pointer_counter, sizeof(serverHmacKeyParamClearLen));
        serverHmacKeyParamClearLen = ntohl(serverHmacKeyParamClearLen);
        if (pointer_counter > numeric_limits<uint64_t>::max() - sizeof(serverHmacKeyParamClearLen))
        {
            return false;
        }
        pointer_counter += sizeof(serverHmacKeyParamClearLen);

        memcpy(&encryptedSignLen, serialized_pkt_received + pointer_counter, sizeof(encryptedSignLen));
        encryptedSignLen = ntohl(encryptedSignLen);
        if (pointer_counter > numeric_limits<uint64_t>::max() - sizeof(encryptedSignLen))
        {
            return false;
        }
        pointer_counter += sizeof(encryptedSignLen);

        iv = (unsigned char *)malloc(IV_LENGTH);
        if (!iv)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            return false;
        }
        memcpy(iv, serialized_pkt_received + pointer_counter, IV_LENGTH);
        if (pointer_counter > numeric_limits<uint64_t>::max() - IV_LENGTH)
        {
            return false;
        }
        pointer_counter += IV_LENGTH;

        serverSymmetricKeyParamClear = deserializeKey(serialized_pkt_received + pointer_counter, serverSymmetricKeyParamClearLen);
        if (pointer_counter > numeric_limits<uint64_t>::max() - serverSymmetricKeyParamClearLen)
        {
            return false;
        }
        pointer_counter += serverSymmetricKeyParamClearLen;
        if (serverSymmetricKeyParamClear == nullptr)
        {
            cerr << "error in deserialization of symmetric key param" << endl;
            return false;
        }

        serverHmacKeyParamClear = deserializeKey(serialized_pkt_received + pointer_counter, serverHmacKeyParamClearLen);
        if (pointer_counter > numeric_limits<uint64_t>::max() - serverHmacKeyParamClearLen)
        {
            return false;
        }
        pointer_counter += serverHmacKeyParamClearLen;
        if (serverHmacKeyParamClear == nullptr)
        {
            cerr << "error in deserialization of hmac key param" << endl;
            return false;
        }

        encryptedSign = (uint8_t *)malloc(encryptedSignLen);
        if (!encryptedSign)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            return false;
        }
        memcpy(encryptedSign, serialized_pkt_received + pointer_counter, encryptedSignLen);
        if (pointer_counter > numeric_limits<uint64_t>::max() - encryptedSignLen)
        {
            return false;
        }
        pointer_counter += encryptedSignLen;

        return true;
    }

    bool deserialize_message_no_clear_keys(uint8_t *serialized_pkt_received)
    {
        uint64_t pointer_counter = 0;

        if (iv != nullptr)
        {
            iv = nullptr;
        }

        memcpy(&encryptedSignLen, serialized_pkt_received + pointer_counter, sizeof(encryptedSignLen));
        encryptedSignLen = ntohl(encryptedSignLen);
        if (pointer_counter > numeric_limits<uint64_t>::max() - sizeof(encryptedSignLen))
        {
            return false;
        }
        pointer_counter += sizeof(encryptedSignLen);

        iv = (unsigned char *)malloc(IV_LENGTH);
        if (!iv)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            return false;
        }
        memcpy(iv, serialized_pkt_received + pointer_counter, IV_LENGTH);
        if (pointer_counter > numeric_limits<uint64_t>::max() - IV_LENGTH)
        {
            return false;
        }
        pointer_counter += IV_LENGTH;

        encryptedSign = (uint8_t *)malloc(encryptedSignLen);
        if (!encryptedSign)
        {
            cerr << "encrypted signing malloc failed" << endl;
            return false;
        }

        memcpy(encryptedSign, serialized_pkt_received + pointer_counter, encryptedSignLen);

        return true;
    }
};

struct server_info
{
    // Filled before serialization and after deserialization_decrypted
    uint16_t responseCode;
    uint64_t timestamp;
    string responseContent;

    
    bool deserializeServerInfo(uint8_t *to_serialize)
    {
        string delimiter = "|";
        string content = (char*)to_serialize;

        unsigned int pos = 0;
        unsigned int delimiterPos = 0;        

        delimiterPos = content.find(delimiter , pos);
        responseCode = stoi(content.substr(pos , delimiterPos - pos));

        // TODO: check if responseCode is correct
        content = content.substr(delimiterPos + 1);
        delimiterPos = content.find(delimiter, pos);
        timestamp = stoull(content.substr(0,delimiterPos));

        content = content.substr(delimiterPos);
        delimiterPos = content.find(delimiter, pos);
        responseContent = content.substr(delimiterPos + 1);
        
        return true;
    }
    
    string serializePacket()
    {
        return to_string(this->responseCode) + "|" + to_string(this->timestamp) + "|" + this->responseContent;
    }
};

struct communication_pkt
{
    unsigned char* iv;
    uint32_t cipher_len;
    uint8_t* ciphertext;
    unsigned char* HMAC;

    bool deserialize_message(uint8_t *serialized_pkt)
    {
        int pointer_counter = 0;

        iv = (unsigned char *)malloc(IV_LENGTH);
        if (!iv)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            free(serialized_pkt);
            return false;
        }
        memset(iv, 0, IV_LENGTH);
        // Copy of the iv
        memcpy(iv, serialized_pkt + pointer_counter, IV_LENGTH);
        pointer_counter += IV_LENGTH;

        // Copy of the ciphertext length
        memcpy(&cipher_len, serialized_pkt + pointer_counter, sizeof(cipher_len));
        cipher_len = ntohl(cipher_len);
        pointer_counter += sizeof(cipher_len);

        // Check for tainted cipherlen
        if (cipher_len >= MAX_PKT_SIZE)
        {
            cerr << "[ERROR] Possible tainted cipher received!" << endl;
            free(serialized_pkt);
            free(iv);
            return false;
        }

        ciphertext = (uint8_t *)malloc(cipher_len);
        if (!ciphertext)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            free(serialized_pkt);
            free(iv);
            return false;
        }
        memset(ciphertext, 0, cipher_len);
        memcpy(ciphertext, serialized_pkt + pointer_counter, cipher_len);
        pointer_counter += cipher_len;

        HMAC = (unsigned char *)malloc(HMAC_LENGTH);
        if (!HMAC)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            free(serialized_pkt);
            free(ciphertext);
            free(iv);
            return false;
        }
        memset(HMAC, 0, HMAC_LENGTH);

        // Copy of the ciphertext
        memcpy(HMAC, serialized_pkt + pointer_counter, HMAC_LENGTH);
        pointer_counter += HMAC_LENGTH;

        free(serialized_pkt);

        return true;
    }

    int deserialize_code(uint8_t *serialized_decrypted_pkt)
    {

        unsigned short code = -1;

        string s = (char *)serialized_decrypted_pkt;
        string delimiter = "/";
        unsigned int pos;

        // Extract the code
        pos = s.find(delimiter);
        if (pos != string::npos)
        {
            string i = s.substr(0, pos);
            code = stoi(i);
        }

        return code;
    }

    void *serialize_message(int &len)
    {
        uint8_t *serialized_pkt = nullptr;
        int pointer_offset = 0;

        len = (sizeof(cipher_len) + cipher_len + IV_LENGTH + HMAC_LENGTH);

        serialized_pkt = (uint8_t *)malloc(len);
        if (!serialized_pkt)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            return nullptr;
        }

        uint32_t net_cipher_len = htonl(cipher_len);

        // Adding iv
        uint8_t *net_iv = (uint8_t *)iv;
        memcpy(serialized_pkt + pointer_offset, iv, IV_LENGTH);
        pointer_offset += IV_LENGTH;

        // Adding ciphertext len
        memcpy(serialized_pkt + pointer_offset, &net_cipher_len, sizeof(net_cipher_len));
        pointer_offset += sizeof(net_cipher_len);

        // Adding ciphertext
        memcpy(serialized_pkt + pointer_offset, ciphertext, cipher_len);
        pointer_offset += cipher_len;

        // Adding Hmac
        uint8_t *net_hmac = (uint8_t *)HMAC;
        memcpy(serialized_pkt + pointer_offset, HMAC, HMAC_LENGTH);
        pointer_offset += HMAC_LENGTH;

        return serialized_pkt;
    }
};

struct client_info{
    uint8_t operationCode;
    uint64_t timestamp;
    string destAndAmount;

    // TODO: aggiungere controlli
    bool deserializeClientInfo(uint8_t* to_serialize){
        string delimiter = "|";
        string content = (char*)to_serialize;

        unsigned int pos = 0;
        unsigned int delimiterPos = 0;

        delimiterPos = content.find(delimiter, pos);
        operationCode = stoi(content.substr(pos, delimiterPos - pos));

        if(operationCode < 1 || operationCode > 4){
            return false;
        }

        content = content.substr(delimiterPos + 1);
        delimiterPos = content.find(delimiter, pos);
        timestamp = stoull(content.substr(pos, delimiterPos - pos));

        content = content.substr(delimiterPos + 1);
        delimiterPos = content.find(delimiter, pos);
        destAndAmount = content.substr(pos);

        return true;
    }

    string serializePacket(){
        return to_string(this->operationCode) + "|" + to_string(this->timestamp) + "|" + this->destAndAmount;
    }
};