#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#include <cstring>
#include <string>
#include <vector>
#include <string.h>
#include <sys/stat.h>
#include <math.h>
#include <dirent.h>
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <openssl/rand.h>
#include <sstream>
#include <string>
#include <chrono>
#include "./../utils/env.h"
#include "./../utils/packet.h"
#include "./operations.cpp"

using namespace std;

string loggedUser;
string serverPrivKPath = "./src/server/keys/server_privK.pem";
string serverPubKPath = "./src/server/keys/server_pubK.pem";
string userKeyPath;

// Vars
int currentSocket;
int socketListener = -1;
sockaddr_in serverAddress;
unsigned long port;
uint32_t counter = 0;

// Iv
unsigned char *iv = nullptr;
int ivSize = EVP_CIPHER_iv_length(EVP_aes_128_cbc());

// keys
EVP_PKEY *privateKey = nullptr;
unsigned char *symmetricKey = nullptr;
unsigned char *hmacKey = nullptr;
int symmetricKeyLength = EVP_CIPHER_key_length(EVP_aes_128_cbc());
int hmacKeyLength = HMAC_KEY_SIZE;

// Load private key into memory
bool load_private_server_key()
{
    // Open the file where the key is stored
    FILE *file = fopen(serverPrivKPath.c_str(), "r");
    // Set the hardcoded password to open the key
    string password = SERVER_KEY_PWD;
    if (!file)
    {
        return false;
    }
    // Open the key and extract it
    EVP_PKEY *privk = PEM_read_PrivateKey(file, NULL, NULL, (void *)password.c_str());
    fclose(file);
    if (privk == NULL)
    {
        return false;
    }
    // Load the key in memory
    privateKey = privk;
    return true;
}

// Receive message thorugh socket
int receiveMessage(unsigned char *&recv_buffer, uint32_t &len)
{
    ssize_t ret;
    // Receive message length
    ret = recv(currentSocket, &len, sizeof(uint32_t), 0);
    if (ret == 0)
    {
        cerr << "[ERROR] Client disconnected" << endl
             << endl;
        return -2;
    }
    if (ret < 0 || (unsigned long)ret < sizeof(len))
    {
        cerr << "[ERROR] Message length received is too short" << endl
             << endl;
        return -1;
    }
    try
    {
        // Allocate the receiver buffer
        len = ntohl(len);
        recv_buffer = (unsigned char *)malloc(len);
        if (!recv_buffer)
        {
            cerr << "[ERROR] recv_buffer malloc fail" << endl
                 << endl;
            throw 1;
        }
        // Receive message
        ret = recv(currentSocket, recv_buffer, len, 0);
        if (ret == 0)
        {
            cerr << "[ERROR] Client disconnected" << endl
                 << endl;
            throw 2;
        }
        if (ret < 0 || (unsigned long)ret < sizeof(len))
        {
            cerr << "[ERROR] Message received is too short" << endl
                 << endl;
            throw 3;
        }
    }
    catch (int errorCode)
    {
        free(recv_buffer);
        if (errorCode == 2)
        {
            return -2;
        }
        else
        {
            return -1;
        }
    }
    return 0;
}

// Send message through socket
bool sendMessage(void *msg, const uint32_t len)
{
    ssize_t ret;
    uint32_t netLen = htonl(len);
    // Send message length
    ret = send(currentSocket, &netLen, sizeof(netLen), 0);
    // If -1 error it means that no bytes were sent
    if (ret <= 0)
    {
        cerr << "[ERROR] Message length not sent" << endl
             << endl;
        return false;
    }
    // Send message
    ret = send(currentSocket, msg, len, 0);
    // If -1 error it means that no bytes were sent
    if (ret <= 0)
    {
        cerr << "[ERROR] Message not sent" << endl
             << endl;
        return false;
    }
    return true;
}


// Not encrypted pkt to start dialog
void receiveHelloPkt(helloPkt &pkt)
{
    // Receive buffer
    unsigned char *buffer;
    uint32_t len;

    // Receive message
    if (receiveMessage(buffer, len) < 0)
    {
        free(buffer);
        cerr << "[ERROR] some error in receiving wave_pkt" << endl;
        throw exception();
    }

    // Deserialize pkt
    if (!pkt.deserializeMessage(buffer))
    {
        free(buffer);
        if (pkt.clientSymmKeyParam != nullptr)
        {
            EVP_PKEY_free(pkt.clientSymmKeyParam);
        }
        if (pkt.clientHmacKeyParam != nullptr)
        {
            EVP_PKEY_free(pkt.clientHmacKeyParam);
        }
        cerr << "[ERROR] some error in deserialize wave_pkt" << endl;
        throw exception();
    }

    // Check username
    if (!checkUsername(pkt.username))
    {
        free(buffer);
        if (pkt.clientSymmKeyParam != nullptr)
        {
            EVP_PKEY_free(pkt.clientSymmKeyParam);
        }
        if (pkt.clientHmacKeyParam != nullptr)
        {
            EVP_PKEY_free(pkt.clientHmacKeyParam);
        }
        cerr << "[ERROR] username " + pkt.username + " is not registered" << endl;
        throw exception();
    }

    // We set the current user
    loggedUser = pkt.username;
    // We set the path to retrieve the pubK of the user
    userKeyPath = "./src/server/user_keys/" + loggedUser + "_pubK.pem";

    // check if key params are valid
    if (pkt.clientSymmKeyParam == nullptr || pkt.clientHmacKeyParam == nullptr)
    {
        free(buffer);
        if (pkt.clientSymmKeyParam != nullptr)
        {
            EVP_PKEY_free(pkt.clientSymmKeyParam);
        }
        if (pkt.clientHmacKeyParam != nullptr)
        {
            EVP_PKEY_free(pkt.clientHmacKeyParam);
        }
        loggedUser = "";
        userKeyPath = "";
        cerr << "[ERROR] one of the key params is not valid" << endl;
        throw exception();
    }

    // Correct packet
    free(buffer);
}




// Send the server authentication packet
void sendLoginAuthenticationPkt(loginAuthenticationPkt &pkt)
{
    unsigned char *partToEncrypt;
    int len;
    int finalPktLen;
    unsigned int signatureLen;
    unsigned char *toCopy;
    unsigned char *signature;
    unsigned char *cipherText;
    unsigned char *finalPkt;
    int cipherLen;
    int ret;

    // Serialize the part to encrypt
    toCopy = (unsigned char *)pkt.serializePartToEncrypt(len);

    if (toCopy == nullptr)
    {
        cerr << "[ERROR] Couldn't serialize part to Encrypt!" << endl;
        throw exception();
    }

    partToEncrypt = (unsigned char *)malloc(len);

    if (partToEncrypt == nullptr)
    {
        free(toCopy);
        cerr << "[ERROR] Couldn't malloc!" << endl;
        throw exception();
    }

    memcpy(partToEncrypt, toCopy, len);

    // Sign and free the private key
    signature = signMessage(privateKey, partToEncrypt, len, signatureLen);
    if (signature == nullptr)
    {
        free(toCopy);
        free(partToEncrypt);
        cerr << "[ERROR] Couldn't generate Signature!" << endl;
        throw exception();
    }

    // Generate the IV
    iv = generateIV();

    // Encrypt
    ret = cbcEncrypt(signature, signatureLen, cipherText, cipherLen, symmetricKey, iv);
    if (ret != 0)
    {
        free(toCopy);
        free(partToEncrypt);
        free(signature);
        free(iv);
        iv = nullptr;
        cerr << "[ERROR] Couldn't encrypt!" << endl;
        throw exception();
    }

    pkt.iv = iv;
    pkt.encryptedSign = cipherText;
    pkt.encryptedSignLen = cipherLen;

    // Final serialization
    free(toCopy);
    free(partToEncrypt);
    toCopy = (unsigned char *)pkt.serializeMessage(finalPktLen);
    finalPkt = (unsigned char *)malloc(finalPktLen);

    if (!finalPkt)
    {
        free(toCopy);
        free(signature);
        free(iv);
        iv = nullptr;
        free(cipherText);
        cerr << "[ERROR] Couldn't malloc!" << endl;
        throw exception();
    }

    // Copy
    memcpy(finalPkt, toCopy, finalPktLen);
    if (!sendMessage(finalPkt, finalPktLen))
    {
        free(toCopy);
        free(signature);
        free(iv);
        iv = nullptr;
        free(cipherText);
        free(finalPkt);
        cerr << "[ERROR] Couldn't send final pkt!" << endl;
        throw exception();
    }

    // Free memory
    free(toCopy);
    free(signature);
    free(iv);
    iv = nullptr;
    free(cipherText);
    free(finalPkt);
}

// Receive last pkt to finalize the shared secret
void receiveClientAuthenticationPkt(loginAuthenticationPkt &pkt, loginAuthenticationPkt &serverAuthPkt, helloPkt &helloPkt)
{
    int ret;
    unsigned char *buffer;
    uint32_t len;
    unsigned char *signedText;
    int signedTextLen;
    EVP_PKEY *clientPubKey;
    unsigned char *plaintext;
    uint32_t plainlen;

    // Receive message
    if (receiveMessage(buffer, len) < 0)
    {
        cerr << "[ERROR] Couldn't receive client authentication packet!" << endl;
        throw exception();
    }

    // Check if it is consistent with server_auth_pkt
    if (!pkt.deserializeMessageNoClearKeys(buffer))
    {
        free(buffer);
        cerr << "[ERROR] Couldn't deserialize client authentication packet!" << endl;
        throw exception();
    }

    // Decrypt the encrypted part using the derived symmetric key and the received iv
    if (iv != nullptr)
    {
        free(iv);
    }
    iv = nullptr;
    iv = (unsigned char *)malloc(ivSize);
    if (!iv)
    {
        free(buffer);
        cerr << "[ERROR] Couldn't malloc!" << endl;
        throw exception();
    }

    memcpy(iv, pkt.iv, ivSize);
    //free(server_auth_pkt.iv_cbc);
    ret = cbcDecrypt(pkt.encryptedSign, pkt.encryptedSignLen, plaintext, plainlen, symmetricKey, iv);

    if (ret != 0)
    {
        free(buffer);
        free(iv);
        iv = nullptr;
        free(plaintext);
        cerr << "[ERROR] Couldn't decrypt packet content!" << endl;
        throw exception();
    }

    // Extract client's public key
    FILE *clientPubKeyFile = fopen(userKeyPath.c_str(), "r");
    clientPubKey = PEM_read_PUBKEY(clientPubKeyFile, NULL, NULL, NULL);
    fclose(clientPubKeyFile);
    if (clientPubKey == nullptr)
    {
        free(buffer);
        free(iv);
        iv = nullptr;
        free(plaintext);
        cerr << "[ERROR] Couldn't extract client's key!" << endl;
        throw exception();
    }
    pkt.clientSymmetricKeyParam = helloPkt.clientSymmKeyParam;
    pkt.clientSymmetricKeyParamLen = helloPkt.symmetricKeyLen;

    pkt.clientHmacKeyParam = helloPkt.clientHmacKeyParam;
    pkt.clientHmacKeyParamLen = helloPkt.hmacKeyLen;
    
    pkt.serverSymmetricKeyParam = serverAuthPkt.serverSymmetricKeyParamClear;
    pkt.serverSymmetricKeyParamLen = pkt.serverSymmetricKeyParamClearLen;
    
    pkt.serverHmacKeyParam = serverAuthPkt.serverHmacKeyParamClear;
    pkt.serverHmacKeyParamLen = serverAuthPkt.serverHmacKeyParamClearLen;

    // Server serializes as the client did
    unsigned char* toCopy = (unsigned char *)pkt.serializePartToEncrypt(signedTextLen);
    signedText = (unsigned char *)malloc(signedTextLen);
    if (!signedText)
    {
        free(buffer);
        free(iv);
        iv = nullptr;
        free(plaintext);
        free(toCopy);
        cerr << "[ERROR] Couldn't malloc!" << endl;
        throw exception();
    }
    memcpy(signedText, toCopy, signedTextLen);
    // Verify the signature
    ret = verifySignature(clientPubKey, plaintext, plainlen, signedText, signedTextLen);
    if (ret != 0)
    {
        free(buffer);
        free(iv);
        iv = nullptr;
        free(plaintext);
        free(toCopy);
        free(signedText);
        cerr << "[ERROR] Couldn't verify signature!" << endl;
        throw exception();
    }
    // Frees
    free(buffer);
    free(plaintext);
    free(toCopy);
    free(signedText);
}


bool startSession()
{
    int ret;
    struct helloPkt helloPkt;
    struct loginAuthenticationPkt serverAuthPkt;
    struct loginAuthenticationPkt clientAuthPkt;
    unsigned char *clearSymmetricKey;
    unsigned char *clearHmacKey;

    cout << "CONNECTING TO NEW CLIENT" << endl;

    // Receive hello_pkt from client
    try
    {
        receiveHelloPkt(helloPkt);
    }
    catch (...)
    {
        return false;
    }

    cout << "LOGIN SESSION OF USERNAME: " + helloPkt.username << endl;

    // Generate dh keys for the server
    serverAuthPkt.serverSymmetricKeyParamClear = generateDhKey();
    serverAuthPkt.serverSymmetricKeyParam = serverAuthPkt.serverSymmetricKeyParamClear; // TO ENCRYPT

    if (serverAuthPkt.serverSymmetricKeyParam == nullptr)
    {
        cerr << "[ERROR] Couldn't generate session key params!" << endl;
        return false;
    }

    serverAuthPkt.serverHmacKeyParamClear = generateDhKey();
    serverAuthPkt.serverHmacKeyParam = serverAuthPkt.serverHmacKeyParamClear; // TO ENCRYPT

    if (serverAuthPkt.serverHmacKeyParam == nullptr)
    {
        cerr << "[ERROR] Couldn't generate session key params!" << endl;
        return false;
    }

    // set the params sent by client
    serverAuthPkt.clientSymmetricKeyParam = helloPkt.clientSymmKeyParam;
    serverAuthPkt.clientHmacKeyParam = helloPkt.clientHmacKeyParam;

    // derive symmetric key and hmac key, hash them, take a portion of the hash for the 128 bit key
    clearSymmetricKey = deriveSharedSecret(serverAuthPkt.serverSymmetricKeyParam, helloPkt.clientSymmKeyParam);

    if (!clearSymmetricKey)
    {
        cerr << "[ERROR] Couldn't derive symm key!" << endl;
        return false;
    }
    ret = hashKey(symmetricKey, clearSymmetricKey);

    if (ret != 0)
    {
        cerr << "[ERROR] Couldn't hash symm key!" << endl;
        return false;
    }

    clearHmacKey = deriveSharedSecret(serverAuthPkt.serverHmacKeyParam, helloPkt.clientHmacKeyParam);

    if (!clearHmacKey)
    {
        cerr << "[ERROR] Couldn't derive hmac key!" << endl;
        return false;
    }
    ret = hashHmacKey(hmacKey, clearHmacKey);
    //cout << "Hmac key: " << hmac_key << "Size of key: "<< hmac_key_length << endl;

    if (ret != 0)
    {
        cerr << "[ERROR] Couldn't hash hmac key!" << endl;
        return false;
    }

    // Frees since they won't be used anymore
    free(clearSymmetricKey);
    free(clearHmacKey);

    // Encrypt and send login_server_authentication_pkt
    try
    {
        sendLoginAuthenticationPkt(serverAuthPkt);
    }
    catch (...)
    {
        EVP_PKEY_free(helloPkt.clientSymmKeyParam);
        EVP_PKEY_free(helloPkt.clientHmacKeyParam);
        EVP_PKEY_free(serverAuthPkt.serverSymmetricKeyParamClear);
        EVP_PKEY_free(serverAuthPkt.serverHmacKeyParamClear);
        return false;
    }

    cout << "WAITING FOR CLIENT AUTHENTICATION" << endl;

    // Receive client authentication pkt
    try
    {
        receiveClientAuthenticationPkt(clientAuthPkt, serverAuthPkt, helloPkt);
    }
    catch (...)
    {
        EVP_PKEY_free(helloPkt.clientSymmKeyParam);
        EVP_PKEY_free(helloPkt.clientHmacKeyParam);
        EVP_PKEY_free(serverAuthPkt.serverSymmetricKeyParamClear);
        EVP_PKEY_free(serverAuthPkt.serverHmacKeyParamClear);
        return false;
    }

    cout << "CLIENT CORRECTLY AUTHENTICATED" << endl;

    // Frees
    EVP_PKEY_free(helloPkt.clientSymmKeyParam);
    EVP_PKEY_free(helloPkt.clientHmacKeyParam);
    EVP_PKEY_free(serverAuthPkt.serverSymmetricKeyParamClear);
    EVP_PKEY_free(serverAuthPkt.serverHmacKeyParamClear);

    return true;
}

bool encryptGenerateHMACAndSend(string buffer)
{
    // Generic Packet
    communicationPkt pkt;
    unsigned char *ciphertext;
    int cipherlen;
    unsigned char *data;
    int data_length;
    uint32_t MAC_len;
    unsigned char *HMAC;
    unsigned char *generated_MAC;

    // Encryption
    if (cbcEncrypt((unsigned char *)buffer.c_str(), buffer.length(), ciphertext, cipherlen, symmetricKey, iv) != 0)
    {
        cerr << "[ERROR] Couldn't decrypt!" << endl;
        free(ciphertext);
        ciphertext = nullptr;
        return false;
    }

    // Get the HMAC
    generated_MAC = (uint8_t *)malloc(IV_LENGTH + cipherlen + sizeof(cipherlen));
    if (!generated_MAC)
    {
        cerr << "[ERROR] Couldn't malloc!" << endl;
        return false;
    }

    // Clean allocated space and copy
    memset(generated_MAC, 0, IV_LENGTH + cipherlen + sizeof(cipherlen));
    memcpy(generated_MAC, iv, IV_LENGTH);
    memcpy(generated_MAC + IV_LENGTH, &cipherlen, sizeof(cipherlen));
    memcpy(generated_MAC + IV_LENGTH + sizeof(cipherlen), (void *)ciphertext, cipherlen);

    // Generate the HMAC on the receiving side iv||ciphertext
    generate_SHA256_HMAC(generated_MAC, IV_LENGTH + cipherlen + sizeof(cipherlen), HMAC, MAC_len, hmacKey);

    // Initialization of the data to serialize
    pkt.cipherText = (uint8_t *)ciphertext;
    pkt.cipherLen = cipherlen;
    pkt.iv = iv;
    pkt.HMAC = HMAC;

    data = (unsigned char *)pkt.serializeMessage(data_length);

    // If we couldn't serialize the message!
    if (data == nullptr)
    {
        cerr << "[ERROR] Couldn't serialize!" << endl;
        free(generated_MAC);
        generated_MAC = nullptr;
        free(ciphertext);
        ciphertext = nullptr;
        free(pkt.HMAC);
        pkt.HMAC = nullptr;
        return false;
    }

    // Send the message
    if (!sendMessage((void *)data, data_length))
    {
        cerr << "[ERROR] Couldn't send message!" << endl;
        free(generated_MAC);
        generated_MAC = nullptr;
        free(ciphertext);
        ciphertext = nullptr;
        free(pkt.HMAC);
        pkt.HMAC = nullptr;
        free(data);
        data = nullptr;
        return false;
    }

    // Frees
    free(generated_MAC);
    generated_MAC = nullptr;
    free(ciphertext);
    ciphertext = nullptr;
    free(pkt.HMAC);
    pkt.HMAC = nullptr;
    free(data);
    data = nullptr;
    return true;
}

unsigned char *receiveDecryptVerifyHMAC()
{
    unsigned char *data;
    communicationPkt rcvd_pkt;
    uint32_t length_rec;
    unsigned char *plaintxt;
    uint32_t ptlen;
    uint32_t MAC_len;
    uint8_t *generated_MAC;
    uint8_t *HMAC;

    
    // Receive the serialized data
    int ret = receiveMessage(data, length_rec);
    if (ret != 0)
    {
        cerr << "[ERROR] Couldn't receive message, received error: " << ret << endl;
        data = nullptr;
        return nullptr;
    }

    // Deserialize message
    if (!rcvd_pkt.deserializeMessage(data))
    {
        cerr << "[ERROR] Couldn'r deserialize data!" << endl;
        free(data);
        data = nullptr;
        return nullptr;
    }

    free(iv);
    iv = nullptr;
    iv = rcvd_pkt.iv;

    generated_MAC = (uint8_t *)malloc(IV_LENGTH + rcvd_pkt.cipherLen + sizeof(rcvd_pkt.cipherLen));
    if (!generated_MAC)
    {
        cerr << "[ERROR] Couldn't malloc!" << endl;
        return nullptr;
    }

    // Clean allocated space and copy
    memset(generated_MAC, 0, IV_LENGTH + rcvd_pkt.cipherLen + sizeof(rcvd_pkt.cipherLen));
    memcpy(generated_MAC, rcvd_pkt.iv, IV_LENGTH);
    memcpy(generated_MAC + IV_LENGTH, &rcvd_pkt.cipherLen, sizeof(rcvd_pkt.cipherLen));
    memcpy(generated_MAC + IV_LENGTH + sizeof(rcvd_pkt.cipherLen), (void *)rcvd_pkt.cipherText, rcvd_pkt.cipherLen);

    // Generate the HMAC to verify the correctness of the received message
    generate_SHA256_HMAC(generated_MAC, IV_LENGTH + rcvd_pkt.cipherLen + sizeof(rcvd_pkt.cipherLen), HMAC, MAC_len, hmacKey);

    // Verify HMAC
    if (!verifySHA256(HMAC, rcvd_pkt.HMAC))
    {
        cerr << "[ERROR] Couldn't verify HMAC!" << endl;
        free(generated_MAC);
        generated_MAC = nullptr;
        free(rcvd_pkt.HMAC);
        rcvd_pkt.HMAC = nullptr;
        return nullptr;
    }

    // Decrypt the ciphertext and obtain the plaintext
    if (cbcDecrypt((unsigned char *)rcvd_pkt.cipherText, rcvd_pkt.cipherLen, plaintxt, ptlen, symmetricKey, iv) != 0)
    {
        cerr << "[ERROR] Couldn't decrypt!" << endl;
        free(generated_MAC);
        generated_MAC = nullptr;
        free(rcvd_pkt.HMAC);
        rcvd_pkt.HMAC = nullptr;
        return nullptr;
    }
    // Frees
    free(generated_MAC);
    generated_MAC = nullptr;
    free(HMAC);
    HMAC = nullptr;
    free(rcvd_pkt.HMAC);
    rcvd_pkt.HMAC = nullptr;
    return plaintxt;
}

int handleCommand()
{
    unsigned char *plaintxt;
    try
    {
        clientInfo clientPkt;
        string buffer;

        plaintxt = receiveDecryptVerifyHMAC();
        if (plaintxt == nullptr){
            cerr << "[ERROR] Couldn't receive the message and verify it's HMAC!" << endl;
            throw 1; 
        }

        if (!clientPkt.deserializeClientInfo(plaintxt)){
            free(plaintxt);
            cerr << "[ERROR] Couldn't deserialize packet!" << endl;
            throw 2;
        }

        // check freshness with timestamp
        uint64_t currentTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        // if the timestamp received is older than a minute we reject the packet
        if(currentTimestamp - clientPkt.timestamp >= 60000){
            free(plaintxt);
            throw exception();
        }

        switch (clientPkt.operationCode)
        {
        case BALANCE:
        {
            cout << "Received Balance command from " << loggedUser << endl;
            buffer = balance(clientPkt, loggedUser);
            break;
        }
        case TRANSFER:
        {
            cout << "Received Transfer command from " << loggedUser << endl;
            buffer = transfer(clientPkt, loggedUser);
            break;
        }
        case HISTORY:
        {
            cout << "Received History command from " << loggedUser << endl;
            buffer = history(clientPkt, loggedUser);
            break;
        }
        case LOGOUT:
        {
            cout << "Received Logout command from " << loggedUser << endl;
            buffer = logout(clientPkt, loggedUser);
            break;
        }
        default:
        {
            free(plaintxt);
            throw 3;
            cerr << "[ERROR] Generic error!" << endl;
            break;
        }
        }

        iv = generateIV(); // THROWS 0

        // Send a response to the client
        if (!encryptGenerateHMACAndSend(buffer))
        {
            cerr << "[ERROR] Couldn't encrypt and generate the MAC of the packet!" << endl;
            throw 4;
        }

        // Tells the caller that the client has disconnected
        if (clientPkt.operationCode == LOGOUT)
        {
            return 1;
        }
    }
    catch (...)
    {
        cerr << "Impossible manage commands, waiting for client retry" << endl;
    }
    return 0;
}

void ServeClient()
{
    // Load private server key
    if (!load_private_server_key())
    {
        cerr << "[ERROR] Impossible to load private key!" << endl;
        exit(EXIT_FAILURE);
    }

    // Init session
    if(!startSession())
        return;

    cout << "[+]SESSION KEYS HAVE BEEN ESTABLISHED CORRECTLY" << endl
         << endl;

    cout << "[+]-------" << loggedUser << "'s session-------" << endl;

    while (true)
    {
        // Handle command received from client
        int ret = handleCommand();
        // Error in handling the message
        if (ret == -1)
        {
            cerr << "[ERROR] Server has incountered a fatal error, please restart the server!" << endl;
            break;
        }
        else if (ret == 1)
        {
            cout << "Connection with " << loggedUser << " terminated succesfully" << endl;
            break;
        } else if (ret == 2)
        {
            cerr << "Connection with " << loggedUser << " terminated, because of client's crash!" << endl;
            break;
        }
    }
    
    cout << "[+]----End of " << loggedUser << "'s session----" << endl
             << endl;
    
    // Frees
    free(iv);
    free(symmetricKey);
    free(hmacKey);
}

int main(int argc, char **argv)
{
    // Check if port has been specified
    if (argc < 2)
    {
        cerr << "[ERROR] Port parameter is not present!" << endl;
        return -1;
    }
    //cout << "cifratura iniziale del file utenti" << endl;
    //encryptFile("./src/server/files/users.txt.enc" , "OVERWRITE" , "bob $5$RTId3jqpirFuciRL$cSgI0./hE0Vl8rN6yUcZ7gDS9KHd6cy02Xfo14I43i4 6ed3509863adfbe4");
    //encryptFile("./src/server/files/users.txt.enc" , "APPEND" , "\nalice $5$ei6+bfrJQCnH11rm$btjaJ5T/MWFFsT2grbQZxPG9TW52KR1isEKc8LTgDh7 57d67284e4f79fc5");
    //encryptFile("./src/server/files/aliceBalance.txt.enc" , "OVERWRITE" , "57d67284e4f79fc5 100");
    //encryptFile("./src/server/files/bobBalance.txt.enc" , "OVERWRITE" , "6ed3509863adfbe4 200");
    //encryptFile("./src/server/files/aliceHistory.txt.enc" , "APPEND" , "\n");
    //encryptFile("./src/server/files/bobHistory.txt.enc" , "APPEND" , "\n");
    //------ Setting up the server ------//

    // Assign the port
    port = stoul(argv[1]);
    // Configure serverAddress
    memset(&serverAddress, 0, sizeof(serverAddress));
    // Set for IPv4 addresses
    serverAddress.sin_family = AF_INET;
    // Set port
    serverAddress.sin_port = htons(port);
    // We bind to localhost
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    // ipv4 + tcp, if remains -1 then we display an error
    socketListener = socket(AF_INET, SOCK_STREAM, 0);
    if (socketListener == -1)
    {
        cerr << "[ERROR] Socket couldn't be defined!" << endl;
        return -1;
    }
    int reuse = 1;
    if (setsockopt(socketListener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
        cout << "[ERROR] Impossibile settare il REUSE" << endl;
        return -1;
    }

    // Bind and listen for incoming connections to a max of BACKLOG_SIZE pending
    if (bind(socketListener, (sockaddr *)&serverAddress, sizeof(serverAddress)) == -1)
    {
        cerr << "[ERROR] Socket couldn't be binded" << endl;
        return -1;
    }
    if (listen(socketListener, BACKLOG_SIZE) == -1)
    {
        cerr << "[ERROR] Socket has reached max backlog queue size!" << endl;
        return -1;
    }

    cout << "Server setup correctly!" << endl
         << endl;

    //-----------------------------------//

    // Client address structure
    sockaddr_in clientAddress;
    memset(&clientAddress, 0, sizeof(clientAddress));

    while (true)
    {
        socklen_t addressLen = sizeof(clientAddress);
        cout << "Waiting for new client to connect!" << endl
             << endl;
        currentSocket = accept(socketListener, (sockaddr *)&clientAddress, &addressLen);

        // Failed connection
        if (currentSocket == -1)
        {
            cerr << "[ERROR] new connection to client failed" << endl
                 << endl;
            continue;
        }

        ServeClient();

        // Frees
        loggedUser = "";
        userKeyPath = "";
        counter = 0;
    }
    return 0;
}