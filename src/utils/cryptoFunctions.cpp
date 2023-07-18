#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "env.h"

using namespace std;

unsigned char *decryptFile(string fileName)
{
    int ret; 
    string password = SERVER_KEY_PWD;
    string prvkeyFileName = "./src/server/keys/server_privK.pem";

    // Load private key
    FILE *prvkeyFile = fopen(prvkeyFileName.c_str(), "r");
    if (!prvkeyFile)
    {
        cerr << "[ERROR] cannot open file '" << prvkeyFileName << "' (missing?)\n";
        exit(1);
    }
    EVP_PKEY *prvkey = PEM_read_PrivateKey(prvkeyFile, NULL, NULL, (void *)password.c_str());
    fclose(prvkeyFile);
    if (!prvkey)
    {
        cerr << "[ERROR] PEM_read_PrivateKey returned NULL\n";
        exit(1);
    }

    // Open file to decrypt
    FILE *cphrFileToDecrypt = fopen(fileName.c_str(), "rb");
    if (!cphrFileToDecrypt)
    {
        cerr << "[ERROR] cannot open file '" << fileName << "'"<< endl;
        exit(1);
    }

    // Get the file size
    ret = fseek(cphrFileToDecrypt, 0, SEEK_END);
    if (ret != 0)
    {
        cerr << "[ERROR] cannot seek_end in  '" << fileName << "'"<< endl;
        exit(1);
    }
    long int cphrFileSize = ftell(cphrFileToDecrypt);
    ret = fseek(cphrFileToDecrypt, 0, SEEK_SET);
    if (ret != 0)
    {
        cerr << "[ERROR] cannot seek_set in  '" << fileName << "'"<< endl;
        exit(1);
    }
    // Vars
    const EVP_CIPHER *cipherToDecrypt = EVP_aes_128_cbc();
    int encryptedKeyLen = EVP_PKEY_size(prvkey);
    int ivLen = EVP_CIPHER_iv_length(cipherToDecrypt);

    // Check for possible integer overflow in (encrypted_key_len + iv_len)
    if (encryptedKeyLen > INT_MAX - ivLen)
    {
        cerr << "[ERROR] integer overflow (encrypted key too big?)\n";
        exit(1);
    }
    // Check for correct format of the encrypted file
    if (cphrFileSize < encryptedKeyLen + ivLen)
    {
        cerr << "[ERROR] encrypted file with wrong format\n";
        exit(1);
    }

    // Allocate buffers for encrypted key, IV, ciphertext, and plaintext:
    unsigned char *encryptedKey = (unsigned char *)malloc(encryptedKeyLen);
    unsigned char *encryptedIV = (unsigned char *)malloc(ivLen);
    int cphrLen = cphrFileSize - encryptedKeyLen - ivLen;
    unsigned char *cphrBuffer = (unsigned char *)malloc(cphrLen);
    unsigned char *clearBuffer = (unsigned char *)malloc(cphrLen);
    if (!encryptedKey || !encryptedIV || !cphrBuffer || !clearBuffer)
    {
        cerr << "[ERROR] malloc returned NULL (file too big?)\n";
        exit(1);
    }

    // Read the encrypted key, the IV, and the ciphertext from file:
    ret = fread(encryptedKey, 1, encryptedKeyLen, cphrFileToDecrypt);
    if (ret < encryptedKeyLen)
    {
        cerr << "[ERROR] while reading file '" << fileName << "'\n";
        exit(1);
    }
    ret = fread(encryptedIV, 1, ivLen, cphrFileToDecrypt);
    if (ret < ivLen)
    {
        cerr << "[ERROR] while reading file '" << fileName << "'\n";
        exit(1);
    }
    ret = fread(cphrBuffer, 1, cphrLen, cphrFileToDecrypt);
    if (ret < cphrLen)
    {
        cerr << "[ERROR] while reading file '" << fileName << "'\n";
        exit(1);
    }
    fclose(cphrFileToDecrypt);

    // Create the envelope context:
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        cerr << "[ERROR] EVP_CIPHER_CTX_new returned NULL\n";
        exit(1);
    }

    // Decrypt the ciphertext:
    ret = EVP_OpenInit(ctx, cipherToDecrypt, encryptedKey, encryptedKeyLen, encryptedIV, prvkey);
    if (ret == 0)
    {
        cerr << "[ERROR] EVP_OpenInit returned " << ret << "\n";
        exit(1);
    }
    int nd = 0;    // bytes decrypted at each chunk
    int ndtot = 0; // total decrypted bytes
    ret = EVP_OpenUpdate(ctx, clearBuffer, &nd, cphrBuffer, cphrLen);
    if (ret == 0)
    {
        cerr << "[ERROR] EVP_OpenUpdate returned " << ret << "\n";
        exit(1);
    }
    ndtot += nd;
    ret = EVP_OpenFinal(ctx, clearBuffer + ndtot, &nd);
    if (ret == 0)
    {
        cerr << "[ERROR] EVP_OpenFinal returned " << ret << " (corrupted file?)\n";
        exit(1);
    }
    ndtot += nd;
    int clear_size = ndtot;
    string terminator = "";
    unsigned char *result = (unsigned char *)malloc(clear_size + 1);
    memcpy(result, clearBuffer, clear_size);
    memcpy(result + clear_size, (unsigned char *)terminator.c_str(), 1);
    // Frees
    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(prvkey);
    free(encryptedKey);
    free(encryptedIV);
    free(clearBuffer);
    return result;
}

void encryptFile(string fileName, string mode, string text)
{
    int ret; 
    string pubkeyFileName = "./src/server/keys/server_pubK.pem";

    unsigned char *textToEncrypt;
    int textToEncryptLen;
    
    unsigned char *textToInsert = (unsigned char *)text.c_str();
    int textToInsertLen = strlen((const char *)textToInsert);

    if (mode.compare("OVERWRITE") == 0)
    {
        textToEncryptLen = textToInsertLen;
        textToEncrypt = (unsigned char *)malloc(textToEncryptLen);
        memcpy(textToEncrypt, textToInsert, textToEncryptLen);
    }
    else if (mode.compare("APPEND") == 0)
    {
        unsigned char *text_decrypted = decryptFile(fileName);
        int text_decrypted_length = strlen((const char *)text_decrypted);
        textToEncryptLen = text_decrypted_length + textToInsertLen;
        textToEncrypt = (unsigned char *)malloc(textToEncryptLen);
        memcpy(textToEncrypt, text_decrypted, text_decrypted_length);
        memcpy(textToEncrypt + text_decrypted_length, textToInsert, textToInsertLen);
    }

    FILE *pubkeyFile = fopen(pubkeyFileName.c_str(), "r");
    if (!pubkeyFile)
    {
        cerr << "[ERROR] cannot open file '" << pubkeyFileName << "' (missing?)\n";
        exit(1);
    }
    EVP_PKEY *pubkey = PEM_read_PUBKEY(pubkeyFile, NULL, NULL, NULL);
    fclose(pubkeyFile);
    if (!pubkey)
    {
        cerr << "[ERROR] PEM_read_PUBKEY returned NULL\n";
        exit(1);
    }

    // Vars
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    int encryptedKeyLen = EVP_PKEY_size(pubkey);
    int ivLen = EVP_CIPHER_iv_length(cipher);
    int blockSize = EVP_CIPHER_block_size(cipher);

    // Create the envelope context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        cerr << "[ERROR] EVP_CIPHER_CTX_new returned NULL\n";
        exit(1);
    }

    // Allocate buffers for encrypted key and IV:
    unsigned char *encryptedKey = (unsigned char *)malloc(encryptedKeyLen);
    unsigned char *iv = (unsigned char *)malloc(ivLen);
    if (!encryptedKey || !iv)
    {
        cerr << "[ERROR] malloc returned NULL (encrypted key too big?)\n";
        exit(1);
    }

    // Check for possible integer overflow in (clear_size + block_size)
    if (textToEncryptLen > INT_MAX - blockSize)
    {
        cerr << "[ERROR] integer overflow (file too big?)\n";
        exit(1);
    }

    // Allocate a buffer for the ciphertext:
    int chipherBufferSize = textToEncryptLen + blockSize;
    unsigned char *cipherBuffer = (unsigned char *)malloc(chipherBufferSize);
    if (!cipherBuffer)
    {
        cerr << "[ERROR] malloc returned NULL (file too big?)\n";
        exit(1);
    }

    // Encrypt the plaintext:
    ret = EVP_SealInit(ctx, cipher, &encryptedKey, &encryptedKeyLen, iv, &pubkey, 1);
    if (ret <= 0)
    {
        cerr << "[ERROR] EVP_SealInit returned " << ret << "\n";
        exit(1);
    }
    int nc = 0;    // Bytes encrypted at each chunk
    int nctot = 0; // Total encrypted bytes
    ret = EVP_SealUpdate(ctx, cipherBuffer, &nc, textToEncrypt, textToEncryptLen);
    if (ret == 0)
    {
        cerr << "[ERROR] EVP_SealUpdate returned " << ret << "\n";
        exit(1);
    }
    nctot += nc;
    ret = EVP_SealFinal(ctx, cipherBuffer + nctot, &nc);
    if (ret == 0)
    {
        cerr << "[ERROR] EVP_SealFinal returned " << ret << "\n";
        exit(1);
    }
    nctot += nc;
    int cipherSize = nctot;

    // Write the encrypted key, the IV, and the ciphertext into a '.enc' file:
    FILE *cipherFile = fopen(fileName.c_str(), "wb");
    if (!cipherFile)
    {
        cerr << "[ERROR] cannot open file '" << fileName << "' (no permissions?)\n";
        exit(1);
    }
    ret = fwrite(encryptedKey, 1, encryptedKeyLen, cipherFile);
    if (ret < encryptedKeyLen)
    {
        cerr << "[ERROR] Couldn't write on file '" << fileName << "'\n";
        exit(1);
    }
    ret = fwrite(iv, 1, EVP_CIPHER_iv_length(cipher), cipherFile);
    if (ret < EVP_CIPHER_iv_length(cipher))
    {
        cerr << "[ERROR] Couldn't write on file '" << fileName << "'\n";
        exit(1);
    }
    ret = fwrite(cipherBuffer, 1, cipherSize, cipherFile);
    if (ret < cipherSize)
    {
        cerr << "[ERROR] Couldn't write on file '" << fileName << "'\n";
        exit(1);
    }
    fclose(cipherFile);

    // Delete the plaintext from memory:
    memset(textToEncrypt, 0, textToEncryptLen);

    // Frees
    EVP_CIPHER_CTX_free(ctx);
    free(textToEncrypt);
    free(encryptedKey);
    free(iv);
    free(cipherBuffer);
    
}

EVP_PKEY *generateDhKey()
{
    EVP_PKEY *dhParams = nullptr;
    EVP_PKEY_CTX *dhCtx = nullptr;
    EVP_PKEY *dhKey = nullptr;

    int ret;

    try
    {
        // Allocate p and g
        dhParams = EVP_PKEY_new();
        if (!dhParams)
        {
            cerr << "[ERROR] Couldn't generate new dh params!" << endl;
            throw 0;
        }

        // Set default dh parameters for p & g
        DH *defaultParams = DH_get_2048_224();
        ret = EVP_PKEY_set1_DH(dhParams, defaultParams);

        // Delete p & g
        DH_free(defaultParams);

        if (ret != 1)
        {
            cerr << "[ERROR] Couldn't load default params!" << endl;
            throw 0;
        }

        // a or b
        dhCtx = EVP_PKEY_CTX_new(dhParams, nullptr);
        if (!dhCtx)
        {
            cerr << "[ERROR] Couldn't load define dh context!" << endl;
            throw 1;
        }

        ret = EVP_PKEY_keygen_init(dhCtx);
        if (ret != 1)
        {
            cerr << "[ERROR] Couldn't dh keygen init!" << endl;
            throw 1;
        }

        ret = EVP_PKEY_keygen(dhCtx, &dhKey);
        if (ret != 1)
        {
            cerr << "[ERROR] Couldn't dh keygen!" << endl;
            throw 1;
        }
    }
    catch (int errorCode)
    {
        EVP_PKEY_free(dhParams);
        if(errorCode == 1) EVP_PKEY_CTX_free(dhCtx);;
        return nullptr;
    }

    EVP_PKEY_CTX_free(dhCtx);
    EVP_PKEY_free(dhParams);

    return dhKey;
}

// Derive shared symm key
unsigned char *deriveSharedSecret(EVP_PKEY *firstKey, EVP_PKEY *secondKey)
{

    int ret; // Used to return values

    // Create a new context for deriving DH key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(firstKey, nullptr);
    if (!ctx)
    {
        cerr << "[ERROR] Couldn't load define dh context of the current host!" << endl;
        return nullptr;
    }

    unsigned char *sharedSecret = nullptr;
    size_t secretLength = 0;

    // Derive the shared secret between the two hosts
    try
    {
        ret = EVP_PKEY_derive_init(ctx);
        if (ret != 1)
        {
            throw 0;
        }
        ret = EVP_PKEY_derive_set_peer(ctx, secondKey);
        if (ret != 1)
        {
            throw 0;
        }
        ret = EVP_PKEY_derive(ctx, nullptr, &secretLength);
        if (ret != 1)
        {
            throw 0;
        }
        sharedSecret = (unsigned char *)malloc(secretLength);
        if (!sharedSecret)
        {
            throw 1;
        }
    }
    catch (int e)
    {
        if (e == 1)
        {
            cerr << "[ERROR] Couldn't allocate shared secret!" << endl;
        }
        else
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
        }
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    ret = EVP_PKEY_derive(ctx, sharedSecret, &secretLength);
    EVP_PKEY_CTX_free(ctx);
    if (ret != 1)
    {
        memset(sharedSecret, 0, secretLength);
        free(sharedSecret);
        return nullptr;
    }
    return sharedSecret;
}

// Serialize key EVP_PKEY
void *serializeKey(EVP_PKEY *key, uint32_t &keyLen)
{
    int ret;
    long ret_long;
    BIO *bio = nullptr;
    void *key_buffer = nullptr;

    try
    {
        // Allocate an instance of the BIO structure for serialization
        bio = BIO_new(BIO_s_mem());
        if (!bio)
        {
            cerr << "[ERROR] Couldn't BIO_new!" << endl;
            throw 0;
        }

        // Serialize a key into PEM format and write it in the BIO
        ret = PEM_write_bio_PUBKEY(bio, key);
        if (ret != 1)
        {
            BIO_free(bio);
            cerr << "[ERROR] Couldn't PEM_write_bio_PUBKEY with error: " << ret << endl;
            throw 0;
        }

        // Set of the pointer key_buffer to the buffer of the memory bio and return its size
        ret_long = BIO_get_mem_data(bio, &key_buffer);
        if (ret_long <= 0)
        {
            BIO_free(bio);
            cerr << "[ERROR] Couldn't BIO_get_mem_data with error: " << ret_long << endl;
            throw 0;
        }
        keyLen = (uint32_t)ret_long;

        // Allocate memory for the serialized key
        key_buffer = malloc(keyLen);
        if (!key_buffer)
        {
            BIO_free(bio);
            cerr << "[ERROR] Couldn't malloc!" << endl;
            throw 0;
        }

        // Read data from bio and extract serialized key
        ret = BIO_read(bio, key_buffer, keyLen);
        if (ret < 1)
        {
            BIO_free(bio);
            free(key_buffer);
            cerr << "[ERROR] Couldn't BIO_read with error: " << ret << endl;
            throw 1;
        }
    }
    catch (int errorCode)
    {
        BIO_free(bio);
        if(errorCode == 1) free(key_buffer);
        return nullptr;
    }

    // Free
    BIO_free(bio);

    return key_buffer;
}

// Deserialize key EVP_PKEY
EVP_PKEY *deserializeKey(const void *keyBuffer, const uint32_t keyLen)
{
    int ret;
    BIO *bio;
    EVP_PKEY *key;

    try
    {
        // Allocate an instance of the BIO structure for serialization
        bio = BIO_new(BIO_s_mem());
        if (!bio)
        {
            cerr << "[ERROR] Couldn't BIO_new!" << endl;
            throw 0;
        }

        // Write serialized the key from the buffer in bio
        ret = BIO_write(bio, keyBuffer, keyLen);
        if (ret <= 0)
        {
            cerr << "[ERROR] Couldn't BIO_write with error: " << ret << endl;
            throw 1;
        }

        // Reads a key written in PEM format from the bio and deserialize it
        key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        if (!key)
        {
            cerr << "[ERROR] Couldn't PEM_read_bio_PUBKEY!" << endl;
            throw 1;
        }
    }
    catch (int errorCode)
    {
        if(errorCode == 1) BIO_free(bio);;
        return nullptr;
    }

    // Free
    BIO_free(bio);

    return key;
}

// Sign a message using private key prvkey
unsigned char *signMessage(EVP_PKEY *prvKey, const unsigned char *msg, const size_t msgLen, unsigned int &signatureLen)
{
    int ret;
    EVP_MD_CTX *ctx = nullptr;
    unsigned char *signature = nullptr;

    if (!prvKey)
    {
        return nullptr;
    }

    try
    {
        ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            cerr << "[ERROR] Couldn't create new context for signature!" << endl;
            throw 0;
        }

        ret = EVP_SignInit(ctx, EVP_sha256());
        if (ret != 1)
        {
            cerr << "[ERROR] Couldn't sign init!" << endl;
            throw 1;
        }

        ret = EVP_SignUpdate(ctx, msg, msgLen);
        if (ret != 1)
        {
            cerr << "[ERROR] Couldn't sign update!" << endl;
            throw 1;
        }

        signatureLen = EVP_PKEY_size(prvKey);
        signature = (unsigned char *)malloc(signatureLen);
        if (!signature)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            throw 1;
        }

        ret = EVP_SignFinal(ctx, signature, &signatureLen, prvKey);
        if (ret != 1)
        {
            cerr << "[ERROR] Couldn't sign final!" << endl;
            throw 2;
        }
    }
    catch (int errorCode)
    {
        // errorCode = 1
        if(errorCode > 0){
            EVP_MD_CTX_free(ctx);
            if(errorCode == 2) free(signature);
        }
        return nullptr;
    }

    // Frees
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(prvKey);

    return signature;
}

// Verify signature with pubkey
int verifySignature(EVP_PKEY *pubKey, const unsigned char *signature, const size_t signatureLen, const unsigned char *cleartext, const size_t cleartextLen)
{
    EVP_MD_CTX *ctx = nullptr;

    int ret;

    if (!pubKey)
    {
        return -1;
    }

    // verify signature
    try
    {
        ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            cerr << "[ERROR]  Couldn't create new context for signature!" << endl;
            throw 0;
        }

        ret = EVP_VerifyInit(ctx, EVP_sha256());
        if (ret != 1)
        {
            cerr << "[ERROR] Couldn't verify init for signature!" << endl;
            throw 1;
        }

        ret = EVP_VerifyUpdate(ctx, cleartext, cleartextLen);
        if (ret != 1)
        {
            cerr << "[ERROR] Couldn't verify update for signature!" << endl;
            throw 1;
        }

        ret = EVP_VerifyFinal(ctx, signature, signatureLen, pubKey);

        if (ret != 1)
        {
            cerr << "[ERROR] Couldn't verify final for signature!" << endl;
            throw 1;
        }
    }
    catch (int errorCode)
    {
       if(errorCode == 1) EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubKey);

    return 0;
}

// Verify if 2 digest SHA-256 are the same
bool verifySHA256(unsigned char *digest, unsigned char *receivedDigest)
{

    if (CRYPTO_memcmp(digest, receivedDigest, EVP_MD_size(EVP_sha256())) == 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

// Generate SHA-256 HMAC with a 256 bit key
int generate_SHA256_HMAC(unsigned char *msg, size_t msgLen, unsigned char *&digest, uint32_t &digestlen, unsigned char *key)
{
    int ret;
    HMAC_CTX *ctx;

    try
    {
        ctx = HMAC_CTX_new();
        if (!ctx)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            throw 0;
        }

        digest = (unsigned char *)malloc(EVP_MD_size(EVP_sha256()));
        if (!digest)
        {
            cerr << "[ERROR] Couldn't create context definition!" << endl;
            throw 1;
        }

        memset(digest, 0, EVP_MD_size(EVP_sha256()));

        ret = HMAC_Init_ex(ctx, key, EVP_MD_size(EVP_sha256()), EVP_sha256(), NULL);
        if (ret != 1)
        {
            cerr << "[ERROR] Couldn't initialize digest creation!" << endl;
            throw 2;
        }

        ret = HMAC_Update(ctx, (unsigned char *)msg, msgLen);
        if (ret != 1)
        {
            cerr << "[ERROR] Couldn't update digest!" << endl;
            throw 2;
        }

        ret = HMAC_Final(ctx, digest, &digestlen);
        if (ret != 1)
        {
            cerr << "[ERROR] Couldn't finalize digest!" << endl;
            throw 2;
        }

        HMAC_CTX_free(ctx);
        return 0;

    }
    catch (int errorCode)
    {
        if(errorCode > 0){
            free(digest);
            if(errorCode == 2) HMAC_CTX_free(ctx);
        }
        return -1;
    }


}

int hashKey(unsigned char *&symKey, unsigned char *keyToHash){

    unsigned char* hash;
    uint32_t len;
    int ret;
    int aesKeySize = EVP_CIPHER_key_length(EVP_aes_128_cbc());
    EVP_MD_CTX *ctx;

    try
    {
        hash = (unsigned char *)malloc(EVP_MD_size(EVP_sha256()));
        if (!hash)
        {
            cerr << "[ERROR] Couldn't malloc!" << endl;
            throw 0;
        }

        ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            cerr << "[ERROR] Couldn't create context!" << endl;
            throw 1;
        }

        ret = EVP_DigestInit(ctx, EVP_sha256());
        if (ret != 1)
        {
            cerr << "[ERROR] Digest Init error with value: " << ret << endl;
            throw 2;
        }

        ret = EVP_DigestUpdate(ctx, (unsigned char *)keyToHash, aesKeySize);
        if (ret != 1)
        {
            cerr << "[ERROR] Digest Update error with value: " << ret << endl;
            throw 2;
        }

        ret = EVP_DigestFinal(ctx, hash, &len);
        if (ret != 1)
        {
            cerr << "[ERROR] Digest Final error with value: " << ret << endl;
            throw 2;
        }
    }catch(int errorCode){
        if(errorCode > 0){
            free(hash);
            if(errorCode == 2) EVP_MD_CTX_free(ctx);
        }
        return -1;
    }

    // Take a portion of the mac for 128 bits key (AES)
    memcpy(symKey, hash, aesKeySize);

    // Free
    free(hash);

    return 0;
}


unsigned char *generateIV()
{
    unsigned char *iv = nullptr;
    int ivLen = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    iv = (unsigned char *)malloc(ivLen);
    int ret = RAND_bytes(iv, ivLen);
    if (ret != 1 || !iv)
    {
        // Must free if we have an error!
        free(iv);
        iv = nullptr;
        throw 0;
    }
    return iv;
}

int cbcEncrypt(unsigned char *msg, int msgLen, unsigned char *&ciphertext, int &cipherlen, unsigned char *key, unsigned char *iv)
{
    EVP_CIPHER_CTX *ctx;
    int ret;
    int finalLen = 0;
    cipherlen = msgLen + BLOCK_SIZE;

    try{
        
        ciphertext = (unsigned char*)malloc(cipherlen);
        if(!ciphertext){
            cerr << "[ERROR] Couldn't malloc!" << endl;
            throw 0;
        }

        ctx = EVP_CIPHER_CTX_new();
        if(!ctx){
            cerr << "[ERROR] Couldn't create context!" << endl;
            throw 1;
        }

        memset(ciphertext, 0, cipherlen);

        ret = EVP_EncryptInit(ctx , EVP_aes_128_cbc(), key, iv);
        if(ret == 0){
            cerr << "[ERROR] Encrypt Init error with value: " << ret << endl;
            throw 2;
        }

        ret = EVP_EncryptUpdate(ctx, ciphertext, &cipherlen, msg, msgLen);
        if(ret == 0){
            cerr << "[ERROR] Encrypt Update error with value: " << ret << endl;
            throw 2;
        }
        
        ret = EVP_EncryptFinal(ctx, ciphertext + cipherlen, &finalLen);
        if(ret == 0){
            cerr << "[ERROR] Encrypt Final error with value: " << ret << endl;
            throw 2;
        }

        cipherlen += finalLen;
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }catch(int errorCode){

        if(errorCode > 0 ){
            free(ciphertext);
            if(errorCode == 2) EVP_CIPHER_CTX_free(ctx);
        }
        return -1;
    }

}

int cbcDecrypt(unsigned char *ciphertext, int cipherlen, unsigned char *&plaintext, uint32_t &plainlen, unsigned char *key, unsigned char *iv)
{
    int finalLen = 0;
    plainlen = 0;
    int ret;

    EVP_CIPHER_CTX *ctx;


    try{
        plaintext = (unsigned char*)malloc(cipherlen);
        if(!plaintext){
            cerr << "[ERROR] Couldn't malloc!" << endl;
            throw 0;
        }


        ctx = EVP_CIPHER_CTX_new();
        if(!ctx){
            cerr << "[ERROR] Couldn't create context!" << endl;
            throw 1;
        }

        memset(plaintext, 0, cipherlen);

        ret = EVP_DecryptInit(ctx , EVP_aes_128_cbc(), key, iv);
        if(ret == 0){
            cerr << "[ERROR] Decrypt Init error with value: " << ret << endl;
            throw 2;
        }

        ret = EVP_DecryptUpdate(ctx, plaintext, &finalLen, ciphertext, cipherlen);
        if(ret == 0){
            cerr << "[ERROR] Decrypt Update error with value: " << ret << endl;
            throw 2;
        }
        plainlen = finalLen;

        ret = EVP_DecryptFinal(ctx, plaintext + finalLen, &finalLen);
        if(ret == 0){
            cerr << "[ERROR] Decrypt Final error with value: " << ret << endl;
            throw 2;
        }
        plainlen += finalLen;  
        EVP_CIPHER_CTX_free(ctx);

        return 0;
    }catch(int errorCode){

        if(errorCode > 0 ){
            free(plaintext);
            if(errorCode == 2) EVP_CIPHER_CTX_free(ctx);
        }
        return -1;
    }
    
}