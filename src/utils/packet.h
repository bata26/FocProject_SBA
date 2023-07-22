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

        uint16_t netCode = htons(code);
        usernameLen = username.length();
        uint16_t usernameNetLen = htons(usernameLen);

        // Total length of the serialized packet
        len = sizeof(netCode) + sizeof(usernameNetLen) + usernameLen + sizeof(symmetricKeyLen) + sizeof(hmacKeyLen) + symmetricKeyLen + hmacKeyLen;
        serializedPkt = (uint8_t *)malloc(len);
        if (!serializedPkt)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            return nullptr;
        }

        // Copy of the code
        memcpy(serializedPkt, &netCode, sizeof(netCode));
        pointer += sizeof(code);

        // Copy username_len
        memcpy(serializedPkt + pointer, &usernameNetLen, sizeof(usernameNetLen));
        pointer += sizeof(usernameLen);

        // Copy of the username
        uint8_t* username_certified = (uint8_t *)username.c_str();
        memcpy(serializedPkt + pointer, username_certified, usernameLen);
        pointer += usernameLen;

        // Copy of symmetric_key_param_len
        uint32_t symmetricKeyNetLen = htonl(symmetricKeyLen);
        memcpy(serializedPkt + pointer, &symmetricKeyNetLen, sizeof(symmetricKeyNetLen));
        pointer += sizeof(symmetricKeyNetLen);

        // Copy of hmac_key_param_len
        uint32_t hmacKeyNetLen = htonl(hmacKeyLen);
        memcpy(serializedPkt + pointer, &hmacKeyNetLen, sizeof(hmacKeyNetLen));
        pointer += sizeof(hmacKeyNetLen);

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

struct loginAuthenticationPkt
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
    uint32_t serverSymmetricKeyParamLen = 0;
    uint32_t serverHmacKeyParamLen = 0;

    uint32_t clientSymmetricKeyParamLen = 0;
    uint32_t clientHmacKeyParamLen = 0;

    EVP_PKEY* serverSymmetricKeyParam = nullptr;
    EVP_PKEY* serverHmacKeyParam = nullptr;
    
    EVP_PKEY* clientSymmetricKeyParam = nullptr;
    EVP_PKEY* clientHmacKeyParam = nullptr;

    void* serializePartToEncrypt(int &len)
    {
        int pointer = 0;
        uint8_t* serializedContent;

        // Evp serializations to pass data through the network
        void* serverSymmetricKeyBuffer = serializeKey(serverSymmetricKeyParam, serverSymmetricKeyParamLen);
        void* serverHmacKeyBuffer = serializeKey(serverHmacKeyParam, serverHmacKeyParamLen);
        void* clientSymmetricKeyBuffer = serializeKey(clientSymmetricKeyParam, clientSymmetricKeyParamLen);
        void* clientHmacKeyBuffer = serializeKey(clientHmacKeyParam, clientHmacKeyParamLen);

        // Total length
        len = sizeof(serverSymmetricKeyParamLen) + sizeof(serverHmacKeyParamLen) + sizeof(clientSymmetricKeyParamLen) +
              sizeof(clientHmacKeyParamLen) + serverSymmetricKeyParamLen + serverHmacKeyParamLen + clientSymmetricKeyParamLen +
              clientHmacKeyParamLen;

        serializedContent = (uint8_t *)malloc(len);
        if (!serializedContent)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            return nullptr;
        }

        // Get lengths of 4 keys
        uint32_t serverSymmetricKeyParamNetLen = htonl(serverSymmetricKeyParamLen);
        uint32_t serverHmacKeyParamNetLen = htonl(serverHmacKeyParamLen);
        uint32_t clientSymmetricKeyParamNetLen = htonl(clientSymmetricKeyParamLen);
        uint32_t clientHmacKeyParamNetLen = htonl(clientHmacKeyParamLen);

        // Start copying
        memcpy(serializedContent + pointer, &serverSymmetricKeyParamNetLen, sizeof(serverSymmetricKeyParamNetLen));
        pointer += sizeof(serverSymmetricKeyParamNetLen);
        memcpy(serializedContent + pointer, &serverHmacKeyParamNetLen, sizeof(serverHmacKeyParamNetLen));
        pointer += sizeof(serverHmacKeyParamNetLen);
        memcpy(serializedContent + pointer, &clientSymmetricKeyParamNetLen, sizeof(clientSymmetricKeyParamNetLen));
        pointer += sizeof(clientSymmetricKeyParamNetLen);
        memcpy(serializedContent + pointer, &clientHmacKeyParamNetLen, sizeof(clientHmacKeyParamNetLen));
        pointer += sizeof(clientHmacKeyParamNetLen);
        memcpy(serializedContent + pointer, serverSymmetricKeyBuffer, serverSymmetricKeyParamLen);
        pointer += serverSymmetricKeyParamLen;
        memcpy(serializedContent + pointer, serverHmacKeyBuffer, serverHmacKeyParamLen);
        pointer += serverHmacKeyParamLen;
        memcpy(serializedContent + pointer, clientSymmetricKeyBuffer, clientSymmetricKeyParamLen);
        pointer += clientSymmetricKeyParamLen;
        memcpy(serializedContent + pointer, clientHmacKeyBuffer, clientHmacKeyParamLen);
        pointer += clientHmacKeyParamLen;

        // Frees
        free(serverSymmetricKeyBuffer);
        free(serverHmacKeyBuffer);
        free(clientSymmetricKeyBuffer);
        free(clientHmacKeyBuffer);

        return serializedContent;
    }

    void* serializeMessage(int &len)
    {
        int pointer = 0;
        uint8_t* serializedPkt;
        void* serverSymmetricKeyClearBuffer = nullptr;
        void* serverHmacKeyClearBuffer = nullptr;

        if (encryptedSign == nullptr || encryptedSignLen == 0 || iv == nullptr)
        {
            cerr << "[ERROR] Missing field!" << endl;
            return nullptr;
        }

        // Symm_key
        serverSymmetricKeyClearBuffer = serializeKey(serverSymmetricKeyParamClear, serverSymmetricKeyParamClearLen);
        uint32_t serverSymmetricKeyClearNetLen = htonl(serverSymmetricKeyParamClearLen);

        // Hmac_key
        serverHmacKeyClearBuffer = serializeKey(serverHmacKeyParamClear, serverHmacKeyParamClearLen);
        uint32_t serverHmacKeyParamClearNetLen = htonl(serverHmacKeyParamClearLen);

        uint32_t encryptedSignNetLen = htonl(encryptedSignLen);

        //Total len
        len = sizeof(serverSymmetricKeyClearNetLen) + sizeof(serverHmacKeyParamClearNetLen) + sizeof(encryptedSignNetLen) + IV_LENGTH + serverSymmetricKeyParamClearLen + serverHmacKeyParamClearLen + encryptedSignLen;

        serializedPkt = (uint8_t *)malloc(len);
        if (!serializedPkt)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            return nullptr;
        }

        // Start copying
        memcpy(serializedPkt, &serverSymmetricKeyClearNetLen, sizeof(serverSymmetricKeyClearNetLen));
        pointer += sizeof(serverSymmetricKeyClearNetLen);
        memcpy(serializedPkt + pointer, &serverHmacKeyParamClearNetLen, sizeof(serverHmacKeyParamClearNetLen));
        pointer += sizeof(serverHmacKeyParamClearNetLen);
        memcpy(serializedPkt + pointer, &encryptedSignNetLen, sizeof(encryptedSignNetLen));
        pointer += sizeof(encryptedSignLen);
        memcpy(serializedPkt + pointer, iv, IV_LENGTH);
        pointer += IV_LENGTH;
        memcpy(serializedPkt + pointer, serverSymmetricKeyClearBuffer, serverSymmetricKeyParamClearLen);
        pointer += serverSymmetricKeyParamClearLen;
        memcpy(serializedPkt + pointer, serverHmacKeyClearBuffer, serverHmacKeyParamClearLen);
        pointer += serverHmacKeyParamClearLen;
        memcpy(serializedPkt + pointer, encryptedSign, encryptedSignLen);

        // Frees
        free(serverSymmetricKeyClearBuffer);
        free(serverHmacKeyClearBuffer);
        return serializedPkt;
    }

    void* serializeMessageNoClearKeys(int &len)
    {
        int pointer = 0;
        uint8_t* serializedPkt;

        if (encryptedSign == nullptr || encryptedSignLen == 0 || iv == nullptr)
        {
            cerr << "[ERROR] Missing field!" << endl;
            return nullptr;
        }

        uint32_t encryptedSignNetLen = htonl(encryptedSignLen);

        //Total len
        len = sizeof(encryptedSignNetLen) + IV_LENGTH +  encryptedSignLen;

        serializedPkt = (uint8_t *)malloc(len);
        if (!serializedPkt)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            return nullptr;
        }

        // Start copying
        memcpy(serializedPkt + pointer, &encryptedSignNetLen, sizeof(encryptedSignNetLen));
        pointer += sizeof(encryptedSignLen);
        memcpy(serializedPkt + pointer, iv, IV_LENGTH);
        pointer += IV_LENGTH;
        memcpy(serializedPkt + pointer, encryptedSign, encryptedSignLen);

        return serializedPkt;
    }

    bool deserializeMessage(uint8_t* receivedPkt)
    {
        uint64_t pointer = 0;

        if (iv != nullptr)
        {
            iv = nullptr;
        }

        // From the serialized_pkt_received we get all the lengths and then the keys
        memcpy(&serverSymmetricKeyParamClearLen, receivedPkt + pointer, sizeof(serverSymmetricKeyParamClearLen));
        serverSymmetricKeyParamClearLen = ntohl(serverSymmetricKeyParamClearLen);
        if (pointer > numeric_limits<uint64_t>::max() - sizeof(serverSymmetricKeyParamClearLen))
        {
            return false;
        }
        pointer += sizeof(serverSymmetricKeyParamClearLen);

        memcpy(&serverHmacKeyParamClearLen, receivedPkt + pointer, sizeof(serverHmacKeyParamClearLen));
        serverHmacKeyParamClearLen = ntohl(serverHmacKeyParamClearLen);
        if (pointer > numeric_limits<uint64_t>::max() - sizeof(serverHmacKeyParamClearLen))
        {
            return false;
        }
        pointer += sizeof(serverHmacKeyParamClearLen);

        memcpy(&encryptedSignLen, receivedPkt + pointer, sizeof(encryptedSignLen));
        encryptedSignLen = ntohl(encryptedSignLen);
        if (pointer > numeric_limits<uint64_t>::max() - sizeof(encryptedSignLen))
        {
            return false;
        }
        pointer += sizeof(encryptedSignLen);

        iv = (unsigned char *)malloc(IV_LENGTH);
        if (!iv)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            return false;
        }
        memcpy(iv, receivedPkt + pointer, IV_LENGTH);
        if (pointer > numeric_limits<uint64_t>::max() - IV_LENGTH)
        {
            return false;
        }
        pointer += IV_LENGTH;

        serverSymmetricKeyParamClear = deserializeKey(receivedPkt + pointer, serverSymmetricKeyParamClearLen);
        if (pointer > numeric_limits<uint64_t>::max() - serverSymmetricKeyParamClearLen)
        {
            return false;
        }
        pointer += serverSymmetricKeyParamClearLen;
        if (serverSymmetricKeyParamClear == nullptr)
        {
            cerr << "error in deserialization of symmetric key param" << endl;
            return false;
        }

        serverHmacKeyParamClear = deserializeKey(receivedPkt + pointer, serverHmacKeyParamClearLen);
        if (pointer > numeric_limits<uint64_t>::max() - serverHmacKeyParamClearLen)
        {
            return false;
        }
        pointer += serverHmacKeyParamClearLen;
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
        memcpy(encryptedSign, receivedPkt + pointer, encryptedSignLen);
        if (pointer > numeric_limits<uint64_t>::max() - encryptedSignLen)
        {
            return false;
        }
        pointer += encryptedSignLen;

        return true;
    }

    bool deserializeMessageNoClearKeys(uint8_t *receivedPkt)
    {
        uint64_t pointer = 0;

        if (iv != nullptr)
        {
            iv = nullptr;
        }

        memcpy(&encryptedSignLen, receivedPkt + pointer, sizeof(encryptedSignLen));
        encryptedSignLen = ntohl(encryptedSignLen);
        if (pointer > numeric_limits<uint64_t>::max() - sizeof(encryptedSignLen))
        {
            return false;
        }
        pointer += sizeof(encryptedSignLen);

        iv = (unsigned char *)malloc(IV_LENGTH);
        if (!iv)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            return false;
        }
        memcpy(iv, receivedPkt + pointer, IV_LENGTH);
        if (pointer > numeric_limits<uint64_t>::max() - IV_LENGTH)
        {
            return false;
        }
        pointer += IV_LENGTH;

        encryptedSign = (uint8_t *)malloc(encryptedSignLen);
        if (!encryptedSign)
        {
            cerr << "encrypted signing malloc failed" << endl;
            return false;
        }

        memcpy(encryptedSign, receivedPkt + pointer, encryptedSignLen);

        return true;
    }
};

struct serverInfo
{
    // Filled before serialization and after deserialization_decrypted
    uint16_t responseCode;
    uint64_t timestamp;
    string responseContent;

    
    bool deserializeServerInfo(uint8_t *toDeserialize)
    {
        string delimiter = "|";
        string content = (char*)toDeserialize;

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

struct communicationPkt
{
    unsigned char* iv;
    uint32_t cipherLen;
    uint8_t* cipherText;
    unsigned char* HMAC;

    bool deserializeMessage(uint8_t *serializedPkt)
    {
        int pointer = 0;

        iv = (unsigned char *)malloc(IV_LENGTH);
        if (!iv)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            free(serializedPkt);
            return false;
        }
        memset(iv, 0, IV_LENGTH);
        // Copy of the iv
        memcpy(iv, serializedPkt + pointer, IV_LENGTH);
        pointer += IV_LENGTH;

        // Copy of the ciphertext length
        memcpy(&cipherLen, serializedPkt + pointer, sizeof(cipherLen));
        cipherLen = ntohl(cipherLen);
        pointer += sizeof(cipherLen);

        cipherText = (uint8_t *)malloc(cipherLen);
        if (!cipherText)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            free(serializedPkt);
            free(iv);
            return false;
        }
        memset(cipherText, 0, cipherLen);
        memcpy(cipherText, serializedPkt + pointer, cipherLen);
        pointer += cipherLen;

        HMAC = (unsigned char *)malloc(HMAC_LENGTH);
        if (!HMAC)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            free(serializedPkt);
            free(cipherText);
            free(iv);
            return false;
        }
        memset(HMAC, 0, HMAC_LENGTH);

        // Copy of the ciphertext
        memcpy(HMAC, serializedPkt + pointer, HMAC_LENGTH);
        pointer += HMAC_LENGTH;

        free(serializedPkt);

        return true;
    }

    int deserializeCode(uint8_t *serializedPkt)
    {

        unsigned short code = -1;

        string s = (char *)serializedPkt;
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

    void *serializeMessage(int &len)
    {
        uint8_t *serializedPkt = nullptr;
        int pointer = 0;

        len = (sizeof(cipherLen) + cipherLen + IV_LENGTH + HMAC_LENGTH);

        serializedPkt = (uint8_t *)malloc(len);
        if (!serializedPkt)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            return nullptr;
        }

        uint32_t cipherNetLen = htonl(cipherLen);

        // Adding iv
        memcpy(serializedPkt + pointer, iv, IV_LENGTH);
        pointer += IV_LENGTH;

        // Adding ciphertext len
        memcpy(serializedPkt + pointer, &cipherNetLen, sizeof(cipherNetLen));
        pointer += sizeof(cipherNetLen);

        // Adding ciphertext
        memcpy(serializedPkt + pointer, cipherText, cipherLen);
        pointer += cipherLen;

        // Adding Hmac
        memcpy(serializedPkt + pointer, HMAC, HMAC_LENGTH);
        pointer += HMAC_LENGTH;

        return serializedPkt;
    }
};

struct clientInfo{
    uint8_t operationCode;
    uint64_t timestamp;
    string destAndAmount;

    // TODO: aggiungere controlli
    bool deserializeClientInfo(uint8_t* toSerialize){
        string delimiter = "|";
        string content = (char*)toSerialize;

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