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

string server_pubK_path = "./server_pubK.pem";

// iv
unsigned char *iv = nullptr;
int ivSize = EVP_CIPHER_iv_length(EVP_aes_128_cbc());

// Keys
EVP_PKEY *private_key = nullptr;
EVP_PKEY *serverPubk = nullptr;
unsigned char *symmetric_key = nullptr;
unsigned char *hmac_key = nullptr;
int symmetric_key_length = EVP_CIPHER_key_length(EVP_aes_256_gcm());
int hmacKeyLength = HMAC_KEY_SIZE;

uint64_t lastTimestampSended;

// Receive message from socket
int receiveMessage(unsigned char *&recv_buffer, uint32_t &len)
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
        recv_buffer = (unsigned char *)malloc(len);
        if (!recv_buffer)
        {
            cerr << "[ERROR] recv_buffer malloc fail" << endl
                 << endl;
            throw 1;
        }
        // receive message
        ret = recv(sessionSocket, recv_buffer, len, 0);
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
bool send_message(void *msg, const uint32_t hostLen)
{
    ssize_t ret;
    uint32_t actual_len = htonl(hostLen);
    // send message length
    ret = send(sessionSocket, &actual_len, sizeof(actual_len), 0);
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

    pkt.clientSymmKeyParam = generateDhKey();
    pkt.clientHmacKeyParam = generateDhKey();
    
    if (pkt.clientSymmKeyParam == nullptr || pkt.clientHmacKeyParam == nullptr)
    {
        cerr << "[ERROR] Couldn't generate a session key parameter!" << endl;
        throw exception();
    }

    toCopy = (unsigned char *)pkt.serializeMessage(len);

    if (toCopy == nullptr)
    {
        free(toCopy);
        cerr << "[ERROR] Couldn't serialize wave packet!" << endl;
        throw exception();
    }

    buffer = (unsigned char *)malloc(len);

    if (!buffer)
    {
        free(buffer);
        free(toCopy);
        cerr << "[ERROR] Couldn't malloc!" << endl;
        throw exception();
    }

    memcpy(buffer, toCopy, len);

    if (!send_message(buffer, len))
    {
        free(buffer);
        free(toCopy);
        cerr << "[ERROR] Couldn't send wave packet!" << endl;
        throw exception();
    }

    free(buffer);
    free(toCopy);
}

// Receive the server authentication packet
void receive_login_server_authentication(helloPkt &hello_pkt, login_authentication_pkt &pkt)
{
    int ret;
    unsigned char *receive_buffer;
    uint32_t len;
    unsigned char *symmetric_key_no_hashed;
    unsigned char *hmac_key_no_hashed;
    unsigned char *plaintext;
    uint32_t plainlen;
    unsigned char *signed_text;
    int signed_text_len;

    // Receive message
    if (receiveMessage(receive_buffer, len) < 0)
    {
        free(receive_buffer);
        cerr << "[ERROR] Error in the received login_authentication_pkt" << endl;
        throw exception();
    }


    // Deserialize the message to read clearly the message
    if (!pkt.deserialize_message(receive_buffer))
    {
        free(receive_buffer);
        cerr << "[ERROR] some error in deserialize pkt" << endl;
        throw exception();
    }

    // Derive symmetric key and hmac key, hash them and take a portion of the hash for the 128 bit key
    symmetric_key_no_hashed = deriveSharedSecret(hello_pkt.clientSymmKeyParam, pkt.serverSymmetricKeyParamClear);

    if (!symmetric_key_no_hashed)
    {
        free(receive_buffer);
        cerr << "[ERROR] Couldn't derive symmetric key or hmac key!" << endl;
        throw exception();
    }

    ret = hashKey(symmetric_key, symmetric_key_no_hashed);
    if (ret != 0)
    {
        free(receive_buffer);
        cerr << "[ERROR] Couldn't hash symmetric key or hmac key!" << endl;
        throw exception();
    }

    hmac_key_no_hashed = deriveSharedSecret(hello_pkt.clientHmacKeyParam, pkt.serverHmacKeyParamClear);
    if (!hmac_key_no_hashed)
    {
        cerr << "[ERROR] Couldn't derive symmetric key or hmac key!" << endl;
        throw exception();
    }

    ret = hashHmacKey(hmac_key, hmac_key_no_hashed);
    if (ret != 0)
    {
        free(receive_buffer);
        cerr << "[ERROR] Couldn't hash symmetric key or hmac key!" << endl;
        throw exception();
    }

    // Clear the non hashed keys
    free(symmetric_key_no_hashed);
    free(hmac_key_no_hashed);

    // Decrypt using the key and the iv received
    if (iv != nullptr)
    {
        free(iv);
    }

    iv = (unsigned char *)malloc(ivSize);
    if (!iv)
    {
        free(receive_buffer);
        free(iv);
        iv = nullptr;
        cerr << "[ERROR] Couldn't malloc!" << endl;
        throw exception();
    }

    memcpy(iv, pkt.iv, ivSize);
    free(pkt.iv);

    ret = cbcDecrypt(pkt.encryptedSign, pkt.encryptedSignLen, plaintext, plainlen, symmetric_key, iv);

    if (ret != 0)
    {
        free(receive_buffer);
        free(iv);
        iv = nullptr;
        free(plaintext);
        cerr << "[ERROR] Couldn't decrypt server authentication packet!" << endl;
        throw exception();
    }

    // Extract server public key
    FILE *server_pubkey_file = fopen("./src/client/keys/server_pubK.pem", "r");
    serverPubk = PEM_read_PUBKEY(server_pubkey_file, NULL, NULL, NULL);
    fclose(server_pubkey_file);

    if (serverPubk == nullptr)
    {
        free(receive_buffer);
        free(iv);
        iv = nullptr;
        free(plaintext);
        EVP_PKEY_free(serverPubk);
        cerr << "[ERROR] Couldn't extract server's public key!" << endl;
        throw exception();
    }

    // Save received fields
    pkt.symmetric_key_param_server = pkt.serverSymmetricKeyParamClear;
    pkt.symmetric_key_param_len_server = pkt.serverSymmetricKeyParamClearLen;
    pkt.hmac_key_param_server = pkt.serverHmacKeyParamClear;
    pkt.hmac_key_param_len_server = pkt.serverHmacKeyParamClearLen;
    pkt.symmetric_key_param_client = hello_pkt.clientSymmKeyParam;
    pkt.symmetric_key_param_len_client = hello_pkt.symmetricKeyLen;
    pkt.hmac_key_param_client = hello_pkt.clientHmacKeyParam;
    pkt.hmac_key_param_len_client = hello_pkt.hmacKeyLen;

    // We serialize before encrypting and sending
    unsigned char *to_copy = (unsigned char *)pkt.serialize_part_to_encrypt(signed_text_len);

    signed_text = (unsigned char *)malloc(signed_text_len);
    if (!signed_text)
    {
        free(receive_buffer);
        free(iv);
        iv = nullptr;
        free(plaintext);
        EVP_PKEY_free(serverPubk);
        free(signed_text);
        cerr << "[ERROR] Couldn't malloc!" << endl;
        throw exception();
    }
    memcpy(signed_text, to_copy, signed_text_len);

    // Verify the signature
    ret = verifySignature(serverPubk, plaintext, plainlen, signed_text, signed_text_len);
    if (ret != 0)
    {
        free(receive_buffer);
        free(iv);
        iv = nullptr;
        free(plaintext);
        EVP_PKEY_free(serverPubk);
        free(signed_text);
        cerr << "[ERROR] Couldn't verify the signature!" << endl;
        throw exception();
    }

    // Frees
    free(signed_text);
    free(to_copy);
    free(receive_buffer);
    free(plaintext);
}

// Send the client authentication packet encrypted
void send_login_client_authentication(login_authentication_pkt &pkt)
{
    unsigned char *toEncrypt;
    int pte_len;
    int finalLen;
    unsigned int signatureLen;
    unsigned char *signature;
    unsigned char *ciphertext;
    unsigned char *finalPkt;
    unsigned char *toCopy;
    int cipherlen;
    int ret;

    // Serialize the part to encrypt
    toCopy = (unsigned char *)pkt.serialize_part_to_encrypt(pte_len);
    if (toCopy == nullptr){
        cerr << "[ERROR] Couldn't serialize part to encrypt!" << endl;
        throw exception();
    }
    toEncrypt = (unsigned char *)malloc(pte_len);
    if (toEncrypt == nullptr)
    {
        free(toCopy);
        cerr << "[ERROR] Failed malloc!" << endl;
        throw exception();
    }

    memcpy(toEncrypt, toCopy, pte_len);

    // Sign the document
    signature = signMessage(private_key, toEncrypt, pte_len, signatureLen);
    if (signature == nullptr)
    {
        free(toCopy);
        free(toEncrypt);
        cerr << "[ERROR] Couldn't generate signature!" << endl;
        throw exception();
    }

    iv = generateIV(); // THROWSexception()0

    // Encrypt
    ret = cbcEncrypt(signature, signatureLen, ciphertext, cipherlen, symmetric_key, iv);
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

    toCopy = (unsigned char *)pkt.serialize_message_no_clear_keys(finalLen);

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

    if (!send_message(finalPkt, finalLen))
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
bool start_session()
{
    helloPkt hello_pkt;
    login_authentication_pkt server_auth_pkt;
    login_authentication_pkt client_auth_pkt;

    cout << "CONNECTING TO SERVER" << endl;

    // Send wave
    try
    {
        sendFirstPkt(hello_pkt);
    }
    catch (...)
    {
        EVP_PKEY_free(hello_pkt.clientSymmKeyParam);
        EVP_PKEY_free(hello_pkt.clientHmacKeyParam);
        return false;
    }

    cout << "WAITING FOR SERVER AUTHENTICATION" << endl;

    // Receive login_server_authentication_pkt
    try
    {
        receive_login_server_authentication(hello_pkt, server_auth_pkt);
    }
    catch (...)
    {
        return false;
    }

    cout << "SERVER CORRECTLY AUTHENTICATED" << endl;

    client_auth_pkt.symmetric_key_param_server = server_auth_pkt.serverSymmetricKeyParamClear;
    client_auth_pkt.symmetric_key_param_len_server = server_auth_pkt.serverSymmetricKeyParamClearLen;
    client_auth_pkt.hmac_key_param_server = server_auth_pkt.serverHmacKeyParamClear;
    client_auth_pkt.hmac_key_param_len_server = server_auth_pkt.serverHmacKeyParamClearLen;
    client_auth_pkt.symmetric_key_param_client = hello_pkt.clientSymmKeyParam;
    client_auth_pkt.symmetric_key_param_len_client = hello_pkt.symmetricKeyLen;
    client_auth_pkt.hmac_key_param_client = hello_pkt.clientHmacKeyParam;
    client_auth_pkt.hmac_key_param_len_client = hello_pkt.hmacKeyLen;

    // Send login_client_authentication_pkt
    try
    {
        send_login_client_authentication(client_auth_pkt);
    }
    catch (...)
    {
        return false;
    }

    // Frees
    EVP_PKEY_free(hello_pkt.clientSymmKeyParam);
    EVP_PKEY_free(hello_pkt.clientHmacKeyParam);
    EVP_PKEY_free(server_auth_pkt.serverSymmetricKeyParamClear);
    EVP_PKEY_free(server_auth_pkt.serverHmacKeyParamClear);

    return true;
}

bool encrypt_generate_HMAC_and_send(string buffer)
{
    // Generic Packet
    communication_pkt pkt;
    unsigned char* ciphertext;
    int cipherlen;
    unsigned char* data;
    int pkt_size;
    uint32_t MAC_len;
    unsigned char* HMAC;
    unsigned char* generated_MAC;

    // Encryption
    if (cbcEncrypt((unsigned char *)buffer.c_str(), buffer.length(), ciphertext, cipherlen, symmetric_key, iv) != 0)
    {
        cerr << "[ERROR] Couldn't encrypt!" << endl;
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
    generate_SHA256_HMAC(generated_MAC, IV_LENGTH + cipherlen + sizeof(cipherlen), HMAC, MAC_len, hmac_key);

    // Initialization of the data to serialize
    pkt.ciphertext = (uint8_t *)ciphertext;
    pkt.cipher_len = cipherlen;
    pkt.iv = iv;
    pkt.HMAC = HMAC;

    data = (unsigned char *)pkt.serialize_message(pkt_size);
 
    //If we couldn't serialize the message!
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
    if (!send_message((void *)data, pkt_size))
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

unsigned char* receive_decrypt_and_verify_HMAC()
{
    unsigned char* data;
    communication_pkt rcvd_pkt;
    uint32_t length_rec;
    unsigned char* plaintxt;
    uint32_t ptlen;
    uint32_t MAC_len;
    uint8_t* generated_MAC;
    uint8_t* HMAC;

    // Receive the serialized data
    int ret = receiveMessage(data, length_rec);
    if (ret != 0)
    {
        cerr << "[ERROR] some error in receiving MSG, received error: " << ret << endl;
        free(data);
        data = nullptr;
        return nullptr;
    }

    // Deserialize message
    if (!rcvd_pkt.deserialize_message(data))
    {
        cerr << "Error during deserialization of the data" << endl;
        free(data);
        data = nullptr;
        return nullptr;
    }

    free(iv);
    iv = nullptr;
    iv = rcvd_pkt.iv;

    generated_MAC = (uint8_t *)malloc(IV_LENGTH + rcvd_pkt.cipher_len + sizeof(rcvd_pkt.cipher_len));
    if (!generated_MAC)
    {
        cerr << "Error during malloc of generated_MAC" << endl;
        return nullptr;
    }

    // Clean allocated space and copy
    memset(generated_MAC, 0, IV_LENGTH + rcvd_pkt.cipher_len + sizeof(rcvd_pkt.cipher_len));
    memcpy(generated_MAC, rcvd_pkt.iv, IV_LENGTH);
    memcpy(generated_MAC + IV_LENGTH, &rcvd_pkt.cipher_len, sizeof(rcvd_pkt.cipher_len));
    memcpy(generated_MAC + IV_LENGTH + sizeof(rcvd_pkt.cipher_len), (void *)rcvd_pkt.ciphertext, rcvd_pkt.cipher_len);

    // Generate the HMAC to verify the correctness of the received message
    generate_SHA256_HMAC(generated_MAC, IV_LENGTH + rcvd_pkt.cipher_len + sizeof(rcvd_pkt.cipher_len), HMAC, MAC_len, hmac_key);

    // Verify HMAC
    if (!verifySHA256(HMAC, rcvd_pkt.HMAC))
    {
        cerr << "[ERROR] Couldn't verify HMAC, try again" << endl;
        free(generated_MAC);
        generated_MAC = nullptr;
        free(rcvd_pkt.HMAC);
        rcvd_pkt.HMAC = nullptr;
        return nullptr;
    }

    // Decrypt the ciphertext and obtain the plaintext
    if (cbcDecrypt((unsigned char *)rcvd_pkt.ciphertext, rcvd_pkt.cipher_len, plaintxt, ptlen, symmetric_key, iv) != 0)
    {
        cerr << "[ERROR] Couldn't encrypt!" << endl;
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

string send_operation_packet(int operation)
{
    client_info pkt;
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
            throw 6;
        }
        if (receiverName.find_first_not_of(USERNAME_WHITELIST_CHARS) != std::string::npos)
            throw 6;
        cout << "Amount to transfer:" << endl;
        cin >> stringAmount;
        if(!cin)
        {
            throw 6;
        }
        if(stringAmount.find_first_not_of(TRANSFER_WHITELIST_NUMS) != std::string::npos)
            stringAmount = "0";
        amount = stoi(stringAmount);
        if (amount >= 999 || amount <= 0)
            throw 6;
        pkt.destAndAmount = receiverName + "-" + to_string(amount);
    }

    buffer = pkt.serializePacket();
    cout << "sto per inviare : " << buffer << endl;

    iv = generateIV(); // THROWS 0

    if (!encrypt_generate_HMAC_and_send(buffer))
    {
        free(iv);
        iv = nullptr;
        throw 1;
    }

    counter++;
    // Receive the message, check the HMAC validity and decrypt the ciphertext
    unsigned char *plaintxt = receive_decrypt_and_verify_HMAC();
    if (plaintxt == nullptr)
    {
        free(iv);
        iv = nullptr;
        throw 2;
    }

    // Expected packet type
    server_info rcvd_pkt;

    // Deserialize & extracts plaintext (NOTE: Plaintext is freed in the function)
    if (!rcvd_pkt.deserializeServerInfo(plaintxt))
    {
        free(iv);
        iv = nullptr;
        throw 3;
    }

    // Check on rcvd packets values
    if (rcvd_pkt.timestamp != lastTimestampSended)
    {
        free(iv);
        iv = nullptr;
        throw 4;
    }

    // Check the response of the server
    if (rcvd_pkt.responseCode != 200)
    {
        free(iv);
        iv = nullptr;
        throw 5;
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
    string dir = "./src/client/keys/" + username + "_privK.pem";

    cout << dir << endl;
    FILE *file = fopen(dir.c_str(), "r");

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
    private_key = privk;
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
    if (!start_session())
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
        string prov;
        int operation;

        cout << "--------------------------------------------------" << endl
            << "BANK: Insert the operation you want to perform:" << endl
            << "1: Balance(): Returns your bankId and balance" << endl
            << "2: Transfer(User, amount): Sends to the user the amount of money specified" << endl
            << "3: History(): Returns the list of transfers" << endl
            << "4: Logout(): Disconnects from the bank" << endl;
        cout << "ME: ";
        cin >> prov;
        if(!cin)
        {
            cerr << "[ERROR] Couldn't insert operation!" << endl;
            return -1;
        }
        if(prov.find_first_not_of(OPERATION_WHITELIST_NUMS) != std::string::npos)
            prov = "0";
        operation = stoi(prov);
        if (operation >= 5 || operation <= 0)
            operation = 0;

        try
        {
            switch (operation)
            {
            case BALANCE:
            {
                string result = send_operation_packet(BALANCE);
                cout << "[+]BALANCE: " << result << endl;
                break;
            }
            case TRANSFER:
            {
                string result = send_operation_packet(TRANSFER);
                cout << "[+]BANK: Transaction Completed!" << endl;
                break;
            }
            case HISTORY:
            {
                string result = send_operation_packet(HISTORY);
                cout << "[+]BANK: --TRANSACTIONS--" << endl
                     << result << endl;
                break;
            }
            case LOGOUT:
            {
                connected = false;
                string result = send_operation_packet(LOGOUT);
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
        catch (int error_code)
        {
            switch (error_code)
            {
                case 0:
                {
                    cerr << "[ERROR] Couldn't generate iv!" << endl;
                    break;
                }
                case 1:
                {
                    cerr << "[ERROR] Couldn't encrypt and generate HMAC!" << endl;
                    break;
                }
                case 2:
                {
                    cerr << "[ERROR] Could't verify the HMAC of the received message!" << endl;
                    break;
                }
                case 3:
                {
                    cerr << "[ERROR] Could't deserialized the received message!" << endl;
                    break;
                }
                case 4:
                {
                    cerr << "[ERROR] Counter of the the received message is not correct!" << endl;
                    break;
                }
                case 5:
                {
                    cerr << "[ERROR] Operation was not possible!" << endl;
                    break;
                }
                case 6:
                {
                    cerr << "[ERROR] Reformat the request!" << endl;
                    break;
                }
            }
        }
    }
    return 0;
}