#include <stdlib.h>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fstream>
#include <cstdint>
#include <vector>
#include <sys/stat.h>
#include <sstream>
#include <math.h>
#include "./../utils/env.h"
#include "./../utils/packet.h"
#include <chrono>
#include <iostream>

using namespace std;

// Generic vars
string username;
string password;
unsigned long port;
int sessionSocket = -1;
const string serverIp = SERVER_IP;
sockaddr_in serverAddress;
uint32_t counter = 0;

string serverPubKPath = "./server_pubK.pem";

// iv
unsigned char *iv = nullptr;
int ivSize = EVP_CIPHER_iv_length(EVP_aes_128_cbc());

// Keys
EVP_PKEY *privateKey = nullptr;
EVP_PKEY *serverPubk = nullptr;
unsigned char *symmetricKey = nullptr;
unsigned char *hmacKey = nullptr;
int symmetricKeyLength = EVP_CIPHER_key_length(EVP_aes_256_gcm());
int hmacKeyLength = HMAC_KEY_SIZE;

uint64_t lastTimestampSended;

// Receive message from socket
int receiveMessage(unsigned char *&buffer, uint32_t &len)
{
    ssize_t ret;
    // Receive message length
    ret = recv(sessionSocket, &len, sizeof(uint32_t), 0);
    if (ret == 0)
    {
        cerr << "[ERROR] server disconnected" << endl
             << endl;
        return -2;
    }
    if (ret < 0 || (unsigned long)ret < sizeof(len))
    {
        cerr << "[ERROR] message length received is too short" << endl
             << endl;
        return -1;
    }
    try
    {
        // Allocate receive buffer
        len = ntohl(len);
        buffer = (unsigned char *)malloc(len);
        if (!buffer)
        {
            cerr << "[ERROR] recv_buffer malloc fail" << endl
                 << endl;
            throw 1;
        }
        // receive message
        ret = recv(sessionSocket, buffer, len, 0);
        if (ret == 0)
        {
            cerr << "[ERROR] Server disconnected" << endl
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
        free(buffer);
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
bool sendMessage(void *msg, const uint32_t hostLen)
{
    ssize_t ret;
    uint32_t len = htonl(hostLen);
    // send message length
    ret = send(sessionSocket, &len, sizeof(len), 0);
    // -1 error, if returns 0 no bytes are sent
    if (ret <= 0)
    {
        cerr << "Error: message length not sent" << endl;
        return false;
    }
    // send message
    ret = send(sessionSocket, msg, hostLen, 0);
    // -1 error, if returns 0 no bytes are sent
    if (ret <= 0)
    {
        cerr << "Error: message not sent" << endl;
        return false;
    }
    return true;
}

// Send first packet to start the comm
void sendFirstPkt(helloPkt &pkt)
{
    unsigned char *buffer;
    int len;
    unsigned char *toCopy;

    pkt.code = HELLO;
    pkt.username = username;

    // generate DH Params
    pkt.clientSymmKeyParam = generateDhKey();
    pkt.clientHmacKeyParam = generateDhKey();
    
    if (pkt.clientSymmKeyParam == nullptr || pkt.clientHmacKeyParam == nullptr)
    {
        cerr << "[ERROR] Couldn't generate a session key parameter!" << endl;
        throw exception();
    }

    // serialize message
    toCopy = (unsigned char *)pkt.serializeMessage(len);

    if (toCopy == nullptr)
    {
        free(toCopy);
        cerr << "[ERROR] Couldn't serialize hello packet!" << endl;
        throw exception();
    }

    // malloc buffer for serialized packet
    buffer = (unsigned char *)malloc(len);

    if (!buffer)
    {
        free(buffer);
        free(toCopy);
        cerr << "[ERROR] Couldn't malloc!" << endl;
        throw exception();
    }
    
    // copy serialized packet in buffer
    memcpy(buffer, toCopy, len);

    if (!sendMessage(buffer, len))
    {
        free(buffer);
        free(toCopy);
        cerr << "[ERROR] Couldn't send hello packet!" << endl;
        throw exception();
    }

    free(buffer);
    free(toCopy);
}

// Receive the server authentication packet
void receiveLoginAuthenticationFromServer(helloPkt &helloPkt, loginAuthenticationPkt &pkt)
{
    int ret;
    unsigned char *receiveBuffer;
    uint32_t len;
    unsigned char *symmetricKeyNoHashed;
    unsigned char *hmacKeyNoHashed;
    unsigned char *plainText;
    uint32_t plainlen;
    unsigned char *signedText;
    int signedTextLen;

    // Receive message
    if (receiveMessage(receiveBuffer, len) < 0)
    {
        free(receiveBuffer);
        cerr << "[ERROR] Error in the received login_authentication_pkt" << endl;
        throw exception();
    }


    // Deserialize the message to read clearly the message
    if (!pkt.deserializeMessage(receiveBuffer))
    {
        free(receiveBuffer);
        cerr << "[ERROR] some error in deserialize pkt" << endl;
        throw exception();
    }

    // Derive symmetric key and hmac key, hash them and take a portion of the hash for the 128 bit key
    symmetricKeyNoHashed = deriveSharedSecret(helloPkt.clientSymmKeyParam, pkt.serverSymmetricKeyParamClear);

    if (!symmetricKeyNoHashed)
    {
        free(receiveBuffer);
        cerr << "[ERROR] Couldn't derive symmetric key or hmac key!" << endl;
        throw exception();
    }

    ret = hashKey(symmetricKey, symmetricKeyNoHashed);
    if (ret != 0)
    {
        free(receiveBuffer);
        cerr << "[ERROR] Couldn't hash symmetric key or hmac key!" << endl;
        throw exception();
    }

    hmacKeyNoHashed = deriveSharedSecret(helloPkt.clientHmacKeyParam, pkt.serverHmacKeyParamClear);
    if (!hmacKeyNoHashed)
    {
        cerr << "[ERROR] Couldn't derive symmetric key or hmac key!" << endl;
        throw exception();
    }

    ret = hashHmacKey(hmacKey, hmacKeyNoHashed);
    if (ret != 0)
    {
        free(receiveBuffer);
        cerr << "[ERROR] Couldn't hash symmetric key or hmac key!" << endl;
        throw exception();
    }

    // Clear the non hashed keys
    free(symmetricKeyNoHashed);
    free(hmacKeyNoHashed);

    // Decrypt using the key and the iv received
    if (iv != nullptr)
    {
        free(iv);
    }

    iv = (unsigned char *)malloc(ivSize);
    if (!iv)
    {
        free(receiveBuffer);
        free(iv);
        iv = nullptr;
        cerr << "[ERROR] Couldn't malloc!" << endl;
        throw exception();
    }

    memcpy(iv, pkt.iv, ivSize);
    free(pkt.iv);

    ret = cbcDecrypt(pkt.encryptedSign, pkt.encryptedSignLen, plainText, plainlen, symmetricKey, iv);

    if (ret != 0)
    {
        free(receiveBuffer);
        free(iv);
        iv = nullptr;
        free(plainText);
        cerr << "[ERROR] Couldn't decrypt server authentication packet!" << endl;
        throw exception();
    }

    // Extract server public key
    FILE *serverPubKeyFile = fopen("./src/client/keys/server_pubK.pem", "r");
    serverPubk = PEM_read_PUBKEY(serverPubKeyFile, NULL, NULL, NULL);
    fclose(serverPubKeyFile);

    if (serverPubk == nullptr)
    {
        free(receiveBuffer);
        free(iv);
        iv = nullptr;
        free(plainText);
        EVP_PKEY_free(serverPubk);
        cerr << "[ERROR] Couldn't extract server's public key!" << endl;
        throw exception();
    }

    // Save received fields
    pkt.serverSymmetricKeyParam = pkt.serverSymmetricKeyParamClear;
    pkt.serverSymmetricKeyParamLen = pkt.serverSymmetricKeyParamClearLen;

    pkt.serverHmacKeyParam = pkt.serverHmacKeyParamClear;
    pkt.serverHmacKeyParamLen = pkt.serverHmacKeyParamClearLen;

    pkt.clientSymmetricKeyParam = helloPkt.clientSymmKeyParam;
    pkt.clientSymmetricKeyParamLen = helloPkt.symmetricKeyLen;

    pkt.clientHmacKeyParam = helloPkt.clientHmacKeyParam;
    pkt.clientHmacKeyParamLen = helloPkt.hmacKeyLen;

    // We serialize before check the signature
    unsigned char *toCopy = (unsigned char *)pkt.serializePartToEncrypt(signedTextLen);

    signedText = (unsigned char *)malloc(signedTextLen);
    if (!signedText)
    {
        free(receiveBuffer);
        free(iv);
        iv = nullptr;
        free(plainText);
        EVP_PKEY_free(serverPubk);
        free(signedText);
        cerr << "[ERROR] Couldn't malloc!" << endl;
        throw exception();
    }
    memcpy(signedText, toCopy, signedTextLen);

    // Verify the signature
    ret = verifySignature(serverPubk, plainText, plainlen, signedText, signedTextLen);
    if (ret != 0)
    {
        free(receiveBuffer);
        free(iv);
        iv = nullptr;
        free(plainText);
        EVP_PKEY_free(serverPubk);
        free(signedText);
        cerr << "[ERROR] Couldn't verify the signature!" << endl;
        throw exception();
    }

    // Frees
    free(signedText);
    free(toCopy);
    free(receiveBuffer);
    free(plainText);
}

// Send the client authentication packet encrypted
void sendClientAuthenticationPacket(loginAuthenticationPkt &pkt)
{
    unsigned char *toEncrypt;
    int len;
    int finalLen;
    unsigned int signatureLen;
    unsigned char *signature;
    unsigned char *ciphertext;
    unsigned char *finalPkt;
    unsigned char *toCopy;
    int cipherlen;
    int ret;

    // Serialize the part to encrypt
    toCopy = (unsigned char *)pkt.serializePartToEncrypt(len);
    if (toCopy == nullptr){
        cerr << "[ERROR] Couldn't serialize part to encrypt!" << endl;
        throw exception();
    }
    toEncrypt = (unsigned char *)malloc(len);
    if (toEncrypt == nullptr)
    {
        free(toCopy);
        cerr << "[ERROR] Failed malloc!" << endl;
        throw exception();
    }

    memcpy(toEncrypt, toCopy, len);

    // Sign the document
    signature = signMessage(privateKey, toEncrypt, len, signatureLen);
    if (signature == nullptr)
    {
        free(toCopy);
        free(toEncrypt);
        cerr << "[ERROR] Couldn't generate signature!" << endl;
        throw exception();
    }

    iv = generateIV(); // THROWSexception()0

    // Encrypt
    ret = cbcEncrypt(signature, signatureLen, ciphertext, cipherlen, symmetricKey, iv);
    if (ret != 0)
    {
        free(toCopy);
        free(toEncrypt);
        free(signature);
        cerr << "[ERROR] Couldn't generate ciphertext!" << endl;
        throw exception();
    }

    // Assign to packet values
    pkt.iv = iv;
    pkt.encryptedSign = ciphertext;
    pkt.encryptedSignLen = cipherlen;

    // Final serialization
    free(toCopy);
    free(toEncrypt);

    toCopy = (unsigned char *)pkt.serializeMessageNoClearKeys(finalLen);

    finalPkt = (unsigned char *)malloc(finalLen);
    if (!finalPkt)
    {
        free(ciphertext);
        free(iv);
        iv = nullptr;
        free(signature);
        free(toCopy);
        free(finalPkt);
        throw exception();
    }

    memcpy(finalPkt, toCopy, finalLen);

    if (!sendMessage(finalPkt, finalLen))
    {
        free(ciphertext);
        free(iv);
        iv = nullptr;
        free(signature);
        free(toCopy);
        free(finalPkt);
        cerr << "[ERROR] Couldn't send message" << endl;
        throw exception();
    }

    // Frees
    free(ciphertext);
    free(iv);
    iv = nullptr;
    free(signature);
    free(toCopy);
    free(finalPkt);
}

// Function to establish a symmetric key
bool startSession()
{
    helloPkt helloPkt;
    loginAuthenticationPkt serverAuthPkt;
    loginAuthenticationPkt clientAuthPkt;

    cout << "CONNECTING TO SERVER" << endl;

    // Send wave
    try
    {
        sendFirstPkt(helloPkt);
    }
    catch (...)
    {
        EVP_PKEY_free(helloPkt.clientSymmKeyParam);
        EVP_PKEY_free(helloPkt.clientHmacKeyParam);
        return false;
    }

    cout << "WAITING FOR SERVER AUTHENTICATION" << endl;

    // Receive server authentication packet
    try
    {
        receiveLoginAuthenticationFromServer(helloPkt, serverAuthPkt);
    }
    catch (...)
    {
        return false;
    }

    cout << "SERVER CORRECTLY AUTHENTICATED" << endl;

    clientAuthPkt.serverSymmetricKeyParam = serverAuthPkt.serverSymmetricKeyParamClear;
    clientAuthPkt.serverSymmetricKeyParamLen = serverAuthPkt.serverSymmetricKeyParamClearLen;

    clientAuthPkt.serverHmacKeyParam = serverAuthPkt.serverHmacKeyParamClear;
    clientAuthPkt.serverHmacKeyParamLen = serverAuthPkt.serverHmacKeyParamClearLen;
    
    clientAuthPkt.clientSymmetricKeyParam = helloPkt.clientSymmKeyParam;
    clientAuthPkt.clientSymmetricKeyParamLen = helloPkt.symmetricKeyLen;
    
    clientAuthPkt.clientHmacKeyParam = helloPkt.clientHmacKeyParam;
    clientAuthPkt.clientHmacKeyParamLen = helloPkt.hmacKeyLen;

    // Send login_client_authentication_pkt
    try
    {
        sendClientAuthenticationPacket(clientAuthPkt);
    }
    catch (...)
    {
        return false;
    }

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
    unsigned char* ciphertext;
    int cipherlen;
    unsigned char* data;
    int pktSize;
    uint32_t MACLen;
    unsigned char* HMAC;
    unsigned char* generatedMAC;

    // Encryption
    if (cbcEncrypt((unsigned char *)buffer.c_str(), buffer.length(), ciphertext, cipherlen, symmetricKey, iv) != 0)
    {
        cerr << "[ERROR] Couldn't encrypt!" << endl;
        return false;
    }

    // Get the HMAC
    generatedMAC = (uint8_t *)malloc(IV_LENGTH + cipherlen + sizeof(cipherlen));
    if (!generatedMAC)
    {
        cerr << "[ERROR] Couldn't malloc!" << endl;
        return false;
    }

    // Clean allocated space and copy
    memset(generatedMAC, 0, IV_LENGTH + cipherlen + sizeof(cipherlen));
    memcpy(generatedMAC, iv, IV_LENGTH);
    memcpy(generatedMAC + IV_LENGTH, &cipherlen, sizeof(cipherlen));
    memcpy(generatedMAC + IV_LENGTH + sizeof(cipherlen), (void *)ciphertext, cipherlen);

    // Generate the HMAC on the receiving side iv||ciphertext
    generate_SHA256_HMAC(generatedMAC, IV_LENGTH + cipherlen + sizeof(cipherlen), HMAC, MACLen, hmacKey);

    // Initialization of the data to serialize
    pkt.cipherText = (uint8_t *)ciphertext;
    pkt.cipherLen = cipherlen;
    pkt.iv = iv;
    pkt.HMAC = HMAC;

    data = (unsigned char *)pkt.serializeMessage(pktSize);
 
    //If we couldn't serialize the message!
    if (data == nullptr)
    {
        cerr << "[ERROR] Couldn't serialize!" << endl;
        free(generatedMAC);
        generatedMAC = nullptr;
        free(ciphertext);
        ciphertext = nullptr;
        free(pkt.HMAC);
        pkt.HMAC = nullptr;
        return false;
    }

    // Send the message
    if (!sendMessage((void *)data, pktSize))
    {
        cerr << "[ERROR] Couldn't send message!" << endl;
        free(generatedMAC);
        generatedMAC = nullptr;
        free(ciphertext);
        ciphertext = nullptr;
        free(pkt.HMAC);
        pkt.HMAC = nullptr;
        free(data);
        data = nullptr;
        return false;
    }

    // Frees
    free(generatedMAC);
    generatedMAC = nullptr;
    free(ciphertext);
    ciphertext = nullptr;
    free(pkt.HMAC);
    pkt.HMAC = nullptr;
    free(data);
    data = nullptr;
    return true;
}

unsigned char* receiveDecryptVerifyHMAC()
{
    unsigned char* data;
    communicationPkt rcvdPkt;
    uint32_t receivedLen;
    unsigned char* plainTxt;
    uint32_t plainTxtLen;
    uint32_t MACLen;
    uint8_t* generatedMAC;
    uint8_t* HMAC;

    // Receive the serialized data
    int ret = receiveMessage(data, receivedLen);
    if (ret != 0)
    {
        cerr << "[ERROR] some error in receiving MSG, received error: " << ret << endl;
        free(data);
        data = nullptr;
        return nullptr;
    }

    // Deserialize message
    if (!rcvdPkt.deserializeMessage(data))
    {
        cerr << "Error during deserialization of the data" << endl;
        free(data);
        data = nullptr;
        return nullptr;
    }

    free(iv);
    iv = nullptr;
    iv = rcvdPkt.iv;

    generatedMAC = (uint8_t *)malloc(IV_LENGTH + rcvdPkt.cipherLen + sizeof(rcvdPkt.cipherLen));
    if (!generatedMAC)
    {
        cerr << "Error during malloc of generated_MAC" << endl;
        return nullptr;
    }

    // Clean allocated space and copy
    memset(generatedMAC, 0, IV_LENGTH + rcvdPkt.cipherLen + sizeof(rcvdPkt.cipherLen));
    memcpy(generatedMAC, rcvdPkt.iv, IV_LENGTH);
    memcpy(generatedMAC + IV_LENGTH, &rcvdPkt.cipherLen, sizeof(rcvdPkt.cipherLen));
    memcpy(generatedMAC + IV_LENGTH + sizeof(rcvdPkt.cipherLen), (void *)rcvdPkt.cipherText, rcvdPkt.cipherLen);

    // Generate the HMAC to verify the correctness of the received message
    generate_SHA256_HMAC(generatedMAC, IV_LENGTH + rcvdPkt.cipherLen + sizeof(rcvdPkt.cipherLen), HMAC, MACLen, hmacKey);

    // Verify HMAC
    if (!verifySHA256(HMAC, rcvdPkt.HMAC))
    {
        cerr << "[ERROR] Couldn't verify HMAC, try again" << endl;
        free(generatedMAC);
        generatedMAC = nullptr;
        free(rcvdPkt.HMAC);
        rcvdPkt.HMAC = nullptr;
        return nullptr;
    }

    // Decrypt the ciphertext and obtain the plaintext
    if (cbcDecrypt((unsigned char *)rcvdPkt.cipherText, rcvdPkt.cipherLen, plainTxt, plainTxtLen, symmetricKey, iv) != 0)
    {
        cerr << "[ERROR] Couldn't encrypt!" << endl;
        free(generatedMAC);
        generatedMAC = nullptr;
        free(rcvdPkt.HMAC);
        rcvdPkt.HMAC = nullptr;
        return nullptr;
    }

    // Frees
    free(generatedMAC);
    generatedMAC = nullptr;
    free(HMAC);
    HMAC = nullptr;
    free(rcvdPkt.HMAC);
    rcvdPkt.HMAC = nullptr;
    return plainTxt;
}

string sendOperationPacket(int operation)
{
    clientInfo pkt;
    pkt.operationCode = operation;
    pkt.destAndAmount = "None-0";
    pkt.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    lastTimestampSended = pkt.timestamp;
    string buffer;

    if (operation == 2)
    {
        string receiverName;
        string stringAmount;
        int amount;
        cout << "Transfering money to user:" << endl;
        cin >> receiverName;
        if(!cin)
        {
            cerr << "[ERROR] Invalid input!" << endl;
            throw 0;
        }
        if (receiverName.find_first_not_of(USERNAME_WHITELIST_CHARS) != std::string::npos){
            cerr << "[ERROR] Invalid input!" << endl;
            throw 0;
        }
        cout << "Amount to transfer:" << endl;
        cin >> stringAmount;
        if(!cin)
        {
            cerr << "[ERROR] Invalid input!" << endl;
            throw 0;
        }
        if(stringAmount.find_first_not_of(TRANSFER_WHITELIST_NUMS) != std::string::npos)
            stringAmount = "0";
        amount = stoi(stringAmount);
        if (amount >= 999 || amount <= 0){
            cerr << "[ERROR] Invalid input!" << endl;
            throw 0;
        }
        pkt.destAndAmount = receiverName + "-" + to_string(amount);
    }

    buffer = pkt.serializePacket();

    iv = generateIV(); // THROWS 0

    if (!encryptGenerateHMACAndSend(buffer))
    {
        free(iv);
        iv = nullptr;
        cerr << "[ERROR] Couldn't encrypt and generate HMAC!" << endl;
        throw 1;
    }

    counter++;
    // Receive the message, check the HMAC validity and decrypt the ciphertext
    unsigned char *plaintxt = receiveDecryptVerifyHMAC();
    if (plaintxt == nullptr)
    {
        free(iv);
        iv = nullptr;
        cerr << "[ERROR] Could't verify the HMAC of the received message!" << endl;
        throw 1;
    }

    // Expected packet type
    serverInfo rcvd_pkt;

    // Deserialize & extracts plaintext (NOTE: Plaintext is freed in the function)
    if (!rcvd_pkt.deserializeServerInfo(plaintxt))
    {
        free(iv);
        iv = nullptr;
        cerr << "[ERROR] Could't deserialized the received message!" << endl;
        throw 1;
    }

    // Check on rcvd packets values
    if (rcvd_pkt.timestamp != lastTimestampSended)
    {
        free(iv);
        iv = nullptr;
        cerr << "[ERROR] Timestamp of the the received message is not correct!" << endl;
        throw 1;
    }

    // Check the response of the server
    if (rcvd_pkt.responseCode != 200)
    {
        free(iv);
        iv = nullptr;
        cerr << "[ERROR] Operation was not possible!" << endl;
        throw 1;
    }

    free(iv);
    iv = nullptr;

    return rcvd_pkt.responseContent;
}

int main(int argc, char **argv)
{
    // Check port
    if (argc < 2)
    {
        cerr << "[ERROR] Port parameter is not present" << endl;
        return -1;
    }
    port = stoul(argv[1]);

    // Input username and check for the length
    cout << "Insert username" << endl;
    cin >> username;
    if (!cin)
    {
        cerr << "[ERROR] Couldn't insert username" << endl;
        return -1;
    }
    if (username.length() > MAX_USERNAME_LENGTH || username.length() <= MIN_USERNAME_LENGTH)
    {
        cerr << "[ERROR] Username length not respected" << endl;
        return -1;
    }
    if (username.find_first_not_of(USERNAME_WHITELIST_CHARS) != std::string::npos)
    {
        cerr << "[ERROR] Username has been poorly formatted" << endl;
        return -1;
    }

    // Input password
    cout << "Insert password" << endl;
    cin >> password;
    if (!cin)
    {
        cerr << "[ERROR] Couldn't insert password" << endl;
        return -1;
    }
    if (password.find_first_not_of(USERNAME_WHITELIST_CHARS) != std::string::npos)
    {
        cerr << "[ERROR] Password has been poorly formatted" << endl;
        return -1;
    }
    cout << endl;

    // private key controls
    string privKeyFilePath = "./src/client/keys/" + username + "_privK.pem";

    FILE *file = fopen(privKeyFilePath.c_str(), "r");

    if (!file)
    {
        cerr << "[ERROR] Username or password are wrong" << endl;
        return -1;
    }

    // Tries to convalidate the password protected key
    EVP_PKEY *privk = PEM_read_PrivateKey(file, NULL, NULL, (void *)password.c_str());

    fclose(file);

    if (privk == nullptr)
    {
        cerr << "[ERROR] Username or password are wrong" << endl;
        return -1;
    }

    // Saves locally the private key
    privateKey = privk;
    cout << "Valid credentials!" << endl;

    // socket initialization
    sessionSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (sessionSocket < 0)
    {
        cerr << "[ERROR] Socket creation failed" << endl;
        return -1;
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr(serverIp.c_str());
    serverAddress.sin_port = htons(port);

    // server connection
    if (connect(sessionSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        cerr << "[ERROR] Connection to server failed" << endl;
        return -1;
    }

    // Establish session and HMAC key
    if (!startSession())
    {
        cerr << "[ERROR] Session keys establishment failed" << endl;
        return -1;
    }

    cout << "AUTHENTICATION COMPLETED SUCCESSFULLY" << endl
         << endl;

    //--- Communication betwwen client and server ---//

    bool connected = true;

    cout << "---------------WELCOME TO THE BANK!---------------" << endl;

    while (connected)
    {
        string clientInput;
        int operation;

        cout << "--------------------------------------------------" << endl
            << "BANK: Insert the operation you want to perform:" << endl
            << "1: Balance(): Returns your bankId and balance" << endl
            << "2: Transfer(User, amount): Sends to the user the amount of money specified" << endl
            << "3: History(): Returns the list of transfers" << endl
            << "4: Logout(): Disconnects from the bank" << endl;
        cout << "ME: ";
        cin >> clientInput;
        if(!cin)
        {
            cerr << "[ERROR] Couldn't insert operation!" << endl;
            return -1;
        }
        if(clientInput.find_first_not_of(OPERATION_WHITELIST_NUMS) != std::string::npos)
            clientInput = "0";
        operation = stoi(clientInput);
        if (operation >= 5 || operation <= 0)
            operation = 0;

        try
        {
            switch (operation)
            {
            case BALANCE:
            {
                string result = sendOperationPacket(BALANCE);
                cout << "[+]BANK: " << result << endl;
                break;
            }
            case TRANSFER:
            {
                string result = sendOperationPacket(TRANSFER);
                cout << "[+]BANK: Transaction Completed!" << endl;
                break;
            }
            case HISTORY:
            {
                string result = sendOperationPacket(HISTORY);
                cout << "[+]BANK: TRANSACTIONS LIST" << endl
                     << result << endl;
                break;
            }
            case LOGOUT:
            {
                connected = false;
                string result = sendOperationPacket(LOGOUT);
                cout << "[+]BANK: Bye!" << endl;
                break;
            }
            default:
            {
                cout << "[ERROR]BANK: Operation doesn't exist!" << endl;
                break;
            }
            }
        }
        catch (int errorCode)
        {
            if(errorCode == 1){
                free(iv);
                iv=nullptr;
            }
        }
    }
    return 0;
}