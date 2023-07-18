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
string server_privK_path = "./src/server/keys/server_privK.pem";
string server_pubK_path = "./src/server/keys/server_pubK.pem";
string user_key_path;

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
EVP_PKEY *private_key = nullptr;
unsigned char *symmetric_key = nullptr;
unsigned char *hmac_key = nullptr;
int symmetric_key_length = EVP_CIPHER_key_length(EVP_aes_128_cbc());
int hmacKeyLength = HMAC_KEY_SIZE;

// Load private key into memory
bool load_private_server_key()
{
    // Open the file where the key is stored
    FILE *file = fopen(server_privK_path.c_str(), "r");
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
    private_key = privk;
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
    catch (int error_code)
    {
        free(recv_buffer);
        if (error_code == 2)
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
bool send_message(void *msg, const uint32_t len)
{
    ssize_t ret;
    uint32_t actual_len = htonl(len);
    // Send message length
    ret = send(currentSocket, &actual_len, sizeof(actual_len), 0);
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
void receive_wave_pkt(wave_pkt &pkt)
{
    // Receive buffer
    unsigned char *receive_buffer;
    uint32_t len;

    // Receive message
    if (receiveMessage(receive_buffer, len) < 0)
    {
        free(receive_buffer);
        throw 1;
    }

    // Deserialize pkt
    if (!pkt.deserialize_message(receive_buffer))
    {
        free(receive_buffer);
        if (pkt.symmetric_key_param != nullptr)
        {
            EVP_PKEY_free(pkt.symmetric_key_param);
        }
        if (pkt.hmac_key_param != nullptr)
        {
            EVP_PKEY_free(pkt.hmac_key_param);
        }
        throw 2;
    }

    // Check username
    if (!check_username(pkt.username))
    {
        free(receive_buffer);
        if (pkt.symmetric_key_param != nullptr)
        {
            EVP_PKEY_free(pkt.symmetric_key_param);
        }
        if (pkt.hmac_key_param != nullptr)
        {
            EVP_PKEY_free(pkt.hmac_key_param);
        }
        throw 3;
    }

    // We set the current user
    loggedUser = pkt.username;
    // We set the path to retrieve the pubK of the user
    user_key_path = "./src/server/user_keys/" + loggedUser + "_pubK.pem";

    // check if key params are valid
    if (pkt.symmetric_key_param == nullptr || pkt.hmac_key_param == nullptr)
    {
        free(receive_buffer);
        if (pkt.symmetric_key_param != nullptr)
        {
            EVP_PKEY_free(pkt.symmetric_key_param);
        }
        if (pkt.hmac_key_param != nullptr)
        {
            EVP_PKEY_free(pkt.hmac_key_param);
        }
        loggedUser = "";
        user_key_path = "";
        throw 4;
    }

    // Correct packet
    free(receive_buffer);
}




// Send the server authentication packet
void send_login_server_authentication(login_authentication_pkt &pkt)
{
    unsigned char *part_to_encrypt;
    int pte_len;
    int final_pkt_len;
    unsigned int signature_len;
    unsigned char *to_copy;
    unsigned char *signature;
    unsigned char *ciphertext;
    unsigned char *final_pkt;
    int cipherlen;
    int ret;

    // Serialize the part to encrypt
    to_copy = (unsigned char *)pkt.serialize_part_to_encrypt(pte_len);

    if (to_copy == nullptr)
    {
        throw 1;
    }

    part_to_encrypt = (unsigned char *)malloc(pte_len);

    if (part_to_encrypt == nullptr)
    {
        free(to_copy);
        throw 2;
    }

    memcpy(part_to_encrypt, to_copy, pte_len);

    // Sign and free the private key
    signature = signMessage(private_key, part_to_encrypt, pte_len, signature_len);
    if (signature == nullptr)
    {
        free(to_copy);
        free(part_to_encrypt);
        throw 3;
    }

    // Generate the IV
    iv = generateIV();

    // Encrypt
    ret = cbcEncrypt(signature, signature_len, ciphertext, cipherlen, symmetric_key, iv);
    if (ret != 0)
    {
        free(to_copy);
        free(part_to_encrypt);
        free(signature);
        free(iv);
        iv = nullptr;
        throw 4;
    }

    pkt.iv_cbc = iv;
    pkt.encrypted_signing = ciphertext;
    pkt.encrypted_signing_len = cipherlen;

    // Final serialization
    free(to_copy);
    free(part_to_encrypt);
    to_copy = (unsigned char *)pkt.serialize_message(final_pkt_len);
    final_pkt = (unsigned char *)malloc(final_pkt_len);

    if (!final_pkt)
    {
        free(to_copy);
        free(signature);
        free(iv);
        iv = nullptr;
        free(ciphertext);
        throw 2;
    }

    // Copy
    memcpy(final_pkt, to_copy, final_pkt_len);
    if (!send_message(final_pkt, final_pkt_len))
    {
        free(to_copy);
        free(signature);
        free(iv);
        iv = nullptr;
        free(ciphertext);
        free(final_pkt);
        throw 5;
    }

    // Free memory
    free(to_copy);
    free(signature);
    free(iv);
    iv = nullptr;
    free(ciphertext);
    free(final_pkt);
}

// Receive last pkt to finalize the shared secret
void receive_login_client_authentication(login_authentication_pkt &pkt, login_authentication_pkt &server_auth_pkt, wave_pkt &hello_pkt)
{
    int ret;
    unsigned char *receive_buffer;
    uint32_t len;
    unsigned char *signed_text;
    int signed_text_len;
    EVP_PKEY *client_pubk;
    unsigned char *plaintext;
    uint32_t plainlen;

    // Receive message
    if (receiveMessage(receive_buffer, len) < 0)
    {
        throw 1;
    }

    // Check if it is consistent with server_auth_pkt
    if (!pkt.deserialize_message_no_clear_keys(receive_buffer))
    {
        free(receive_buffer);
        throw 2;
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
        free(receive_buffer);
        throw 3;
    }

    memcpy(iv, pkt.iv_cbc, ivSize);
    //free(server_auth_pkt.iv_cbc);
    ret = cbcDecrypt(pkt.encrypted_signing, pkt.encrypted_signing_len, plaintext, plainlen, symmetric_key, iv);

    if (ret != 0)
    {
        free(receive_buffer);
        free(iv);
        iv = nullptr;
        free(plaintext);
        throw 4;
    }

    // Extract client's public key
    FILE *client_pubk_file = fopen(user_key_path.c_str(), "r");
    client_pubk = PEM_read_PUBKEY(client_pubk_file, NULL, NULL, NULL);
    fclose(client_pubk_file);
    if (client_pubk == nullptr)
    {
        free(receive_buffer);
        free(iv);
        iv = nullptr;
        free(plaintext);
        throw 5;
    }
    pkt.symmetric_key_param_client = hello_pkt.symmetric_key_param;
    pkt.symmetric_key_param_len_client = hello_pkt.symmetric_key_param_len;
    pkt.hmac_key_param_client = hello_pkt.hmac_key_param;
    pkt.hmac_key_param_len_client = hello_pkt.hmac_key_param_len;
    pkt.symmetric_key_param_server = server_auth_pkt.symmetric_key_param_server_clear;
    pkt.symmetric_key_param_len_server = pkt.symmetric_key_param_server_clear_len;
    pkt.hmac_key_param_server = server_auth_pkt.hmac_key_param_server_clear;
    pkt.hmac_key_param_len_server = server_auth_pkt.hmac_key_param_server_clear_len;

    // Server serializes as the client did
    unsigned char* to_copy = (unsigned char *)pkt.serialize_part_to_encrypt(signed_text_len);
    signed_text = (unsigned char *)malloc(signed_text_len);
    if (!signed_text)
    {
        free(receive_buffer);
        free(iv);
        iv = nullptr;
        free(plaintext);
        free(to_copy);
        throw 3;
    }
    memcpy(signed_text, to_copy, signed_text_len);
    // Verify the signature
    ret = verifySignature(client_pubk, plaintext, plainlen, signed_text, signed_text_len);
    if (ret != 0)
    {
        free(receive_buffer);
        free(iv);
        iv = nullptr;
        free(plaintext);
        free(to_copy);
        free(signed_text);
        throw 6;
    }
    // Frees
    free(receive_buffer);
    free(plaintext);
    free(to_copy);
    free(signed_text);
}


bool start_session()
{
    int ret;
    struct wave_pkt hello_pkt;
    struct login_authentication_pkt server_auth_pkt;
    struct login_authentication_pkt client_auth_pkt;
    unsigned char *symmetric_key_no_hashed;
    unsigned char *hmac_key_no_hashed;

    cout << "CONNECTING TO NEW CLIENT" << endl;

    // Receive hello_pkt from client
    try
    {
        receive_wave_pkt(hello_pkt);
    }
    catch (int error_code)
    {
        switch (error_code)
        {
        case 1:
        {
            cerr << "[ERROR] some error in receiving wave_pkt" << endl;
            break;
        }
        case 2:
        {
            cerr << "[ERROR] some error in deserialize wave_pkt" << endl;
            break;
        }
        case 3:
        {
            cerr << "[ERROR] username " + hello_pkt.username + " is not registered" << endl;
            break;
        }
        case 4:
        {
            cerr << "[ERROR] one of the key params is not valid" << endl;
            break;
        }
        }
        return false;
    }

    cout << "LOGIN SESSION OF USERNAME: " + hello_pkt.username << endl;

    // Generate dh keys for the server
    server_auth_pkt.symmetric_key_param_server_clear = generateDhKey();
    server_auth_pkt.symmetric_key_param_server = server_auth_pkt.symmetric_key_param_server_clear; // TO ENCRYPT

    if (server_auth_pkt.symmetric_key_param_server == nullptr)
    {
        cerr << "[ERROR] Couldn't generate session key params!" << endl;
        return false;
    }

    server_auth_pkt.hmac_key_param_server_clear = generateDhKey();
    server_auth_pkt.hmac_key_param_server = server_auth_pkt.hmac_key_param_server_clear; // TO ENCRYPT

    if (server_auth_pkt.hmac_key_param_server == nullptr)
    {
        cerr << "[ERROR] Couldn't generate session key params!" << endl;
        return false;
    }

    // set the params sent by client
    server_auth_pkt.symmetric_key_param_client = hello_pkt.symmetric_key_param;
    server_auth_pkt.hmac_key_param_client = hello_pkt.hmac_key_param;

    // derive symmetric key and hmac key, hash them, take a portion of the hash for the 128 bit key
    symmetric_key_no_hashed = deriveSharedSecret(server_auth_pkt.symmetric_key_param_server, hello_pkt.symmetric_key_param);

    if (!symmetric_key_no_hashed)
    {
        cerr << "[ERROR] Couldn't derive symm key!" << endl;
        return false;
    }
    ret = hashKey(symmetric_key, symmetric_key_no_hashed);

    if (ret != 0)
    {
        cerr << "[ERROR] Couldn't hash symm key!" << endl;
        return false;
    }

    hmac_key_no_hashed = deriveSharedSecret(server_auth_pkt.hmac_key_param_server, hello_pkt.hmac_key_param);

    if (!hmac_key_no_hashed)
    {
        cerr << "[ERROR] Couldn't derive hmac key!" << endl;
        return false;
    }
    ret = hashHmacKey(hmac_key, hmac_key_no_hashed);
    //cout << "Hmac key: " << hmac_key << "Size of key: "<< hmac_key_length << endl;

    if (ret != 0)
    {
        cerr << "[ERROR] Couldn't hash hmac key!" << endl;
        return false;
    }

    // Frees since they won't be used anymore
    free(symmetric_key_no_hashed);
    free(hmac_key_no_hashed);

    // Encrypt and send login_server_authentication_pkt
    try
    {
        send_login_server_authentication(server_auth_pkt);
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
            cerr << "[ERROR] Couldn't serialize part to Encrypt!" << endl;
            break;
        }
        case 2:
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            break;
        }
        case 3:
        {
            cerr << "[ERROR] Couldn't generate a valid Signature!" << endl;
            break;
        }
        case 4:
        {
            cerr << "[ERROR] Couldn't generate a valid Ciphertext!" << endl;
            break;
        }
        case 5:
        {
            cerr << "[ERROR] Couldn't send the final pkt!" << endl;
            break;
        }
        }
        EVP_PKEY_free(hello_pkt.symmetric_key_param);
        EVP_PKEY_free(hello_pkt.hmac_key_param);
        EVP_PKEY_free(server_auth_pkt.symmetric_key_param_server_clear);
        EVP_PKEY_free(server_auth_pkt.hmac_key_param_server_clear);
        return false;
    }

    cout << "WAITING FOR CLIENT AUTHENTICATION" << endl;

    // Receive client authentication pkt
    try
    {
        receive_login_client_authentication(client_auth_pkt, server_auth_pkt, hello_pkt);
    }
    catch (int error_code)
    {
        switch (error_code)
        {
        case 1:
        {
            cerr << "[ERROR] Couldn't receive login_server_authentication_pkt!" << endl;
            break;
        }
        case 2:
        {
            cerr << "[ERROR] Couldn't deserialize client_auth_pkt!" << endl;
            break;
        }
        case 3:
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            break;
        }
        case 4:
        {
            cerr << "[ERROR] Couldn't decrypt the packet!" << endl;
            break;
        }
        case 5:
        {
            cerr << "[ERROR] Couldn't extract client's key!" << endl;
            break;
        }
        case 6:
        {
            cerr << "[ERROR] Couldn't verify signature!" << endl;
            break;
        }
        }
        EVP_PKEY_free(hello_pkt.symmetric_key_param);
        EVP_PKEY_free(hello_pkt.hmac_key_param);
        EVP_PKEY_free(server_auth_pkt.symmetric_key_param_server_clear);
        EVP_PKEY_free(server_auth_pkt.hmac_key_param_server_clear);
        return false;
    }

    cout << "CLIENT CORRECTLY AUTHENTICATED" << endl;

    // Frees
    EVP_PKEY_free(hello_pkt.symmetric_key_param);
    EVP_PKEY_free(hello_pkt.hmac_key_param);
    EVP_PKEY_free(server_auth_pkt.symmetric_key_param_server_clear);
    EVP_PKEY_free(server_auth_pkt.hmac_key_param_server_clear);

    return true;
}

bool encrypt_generate_HMAC_and_send(string buffer)
{
    // Generic Packet
    communication_pkt pkt;
    unsigned char *ciphertext;
    int cipherlen;
    unsigned char *data;
    int data_length;
    uint32_t MAC_len;
    unsigned char *HMAC;
    unsigned char *generated_MAC;

    // Encryption
    if (cbcEncrypt((unsigned char *)buffer.c_str(), buffer.length(), ciphertext, cipherlen, symmetric_key, iv) != 0)
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
    generate_SHA256_HMAC(generated_MAC, IV_LENGTH + cipherlen + sizeof(cipherlen), HMAC, MAC_len, hmac_key);

    // Initialization of the data to serialize
    pkt.ciphertext = (uint8_t *)ciphertext;
    pkt.cipher_len = cipherlen;
    pkt.iv = iv;
    pkt.HMAC = HMAC;

    data = (unsigned char *)pkt.serialize_message(data_length);

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
    if (!send_message((void *)data, data_length))
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

unsigned char *receive_decrypt_and_verify_HMAC()
{
    unsigned char *data;
    communication_pkt rcvd_pkt;
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
    if (!rcvd_pkt.deserialize_message(data))
    {
        cerr << "[ERROR] Couldn'r deserialize data!" << endl;
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
        cerr << "[ERROR] Couldn't malloc!" << endl;
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
        cerr << "[ERROR] Couldn't verify HMAC!" << endl;
        free(generated_MAC);
        generated_MAC = nullptr;
        free(rcvd_pkt.HMAC);
        rcvd_pkt.HMAC = nullptr;
        return nullptr;
    }

    // Decrypt the ciphertext and obtain the plaintext
    if (cbcDecrypt((unsigned char *)rcvd_pkt.ciphertext, rcvd_pkt.cipher_len, plaintxt, ptlen, symmetric_key, iv) != 0)
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

int handle_command()
{
    unsigned char *plaintxt;
    try
    {
        client_info clientPkt;
        string buffer;

        plaintxt = receive_decrypt_and_verify_HMAC();
        if (plaintxt == nullptr){
            throw 1; 
        }

        if (!clientPkt.deserializeClientInfo(plaintxt)){
            free(plaintxt);
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
            break;
        }
        }

        iv = generateIV(); // THROWS 0

        // Send a response to the client
        if (!encrypt_generate_HMAC_and_send(buffer))
        {
            throw 4;
        }

        // Tells the caller that the client has disconnected
        if (clientPkt.operationCode == LOGOUT)
        {
            return 1;
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
            cerr << "[ERROR] Couldn't receive the message or verify it's HMAC!" << endl;
            return 2; //Client crashed!
            break;
        }
        case 2:
        {
            cerr << "[ERROR] Couldn't deserialize packet!" << endl;
            break;
        }
        case 3:
        {
            cerr << "[ERROR] Something went wrong!" << endl;
            break;
        }
        case 4:
        {
            cerr << "[ERROR] Couldn't encrypt and generate the MAC of the packet!" << endl;
            break;
        }
        }
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
    if(!start_session())
        return;

    cout << "[+]SESSION KEYS HAVE BEEN ESTABLISHED CORRECTLY" << endl
         << endl;

    cout << "[+]-------" << loggedUser << "'s session-------" << endl;

    while (true)
    {
        // Handle command received from client
        int ret = handle_command();
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
    
    cout << "//----End of " << loggedUser << "'s session----//" << endl
             << endl;
    
    // Frees
    free(iv);
    free(symmetric_key);
    free(hmac_key);
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
        user_key_path = "";
        counter = 0;
    }
    return 0;
}