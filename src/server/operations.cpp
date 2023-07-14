#include "./utils.cpp"
#include <string.h>

// Returns the balance to the user
string balance(client_info rcv_pkt, string logged_user)
{
    server_info response_pkt;
    string balance = return_balance(logged_user);
    if (balance == ""){
        response_pkt.responseCode = 500;
        response_pkt.responseContent = "Balance Error.";
    }else{
        response_pkt.responseCode = 200;
        response_pkt.responseContent = balance;
    }
    response_pkt.timestamp = rcv_pkt.timestamp;
    
    // Serialize packet
    return response_pkt.serializePacket();
}



// Transfer an amount of money to another user
string transfer(client_info rcv_pkt, string logged_user)
{
    // Build response pkt
    server_info response_pkt;
    string dest;
    int amount;
    string s = rcv_pkt.destAndAmount;
    string delimiter = "-";
    unsigned int pos;

    pos = s.find(delimiter, 0);
    dest = s.substr(0 , pos);
    amount = stoi(s.substr(pos + 1));

    try{
        // check if the username is valid
        if(!check_username(dest)){
            cerr << "[ERROR] Receiver doesn't exist." << endl;
            response_pkt.responseCode = 500;
            response_pkt.responseContent = "Invalid dest";
            throw exception();
        }

        int senderBalance = stoi(return_balance(logged_user));
        if(senderBalance < amount) {
            cerr << "[ERROR] Amount not available." << endl;
            response_pkt.responseCode = 500;
            response_pkt.responseContent = "Invalid amount";
            throw exception();
        }

        uint64_t currentTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        string transactionID = generateID();

        if(transactionID == ""){
            cerr << "[ERROR] Impossible to generate ID" << endl;
            response_pkt.responseCode = 500;
            response_pkt.responseContent = "Generic error";
            throw exception();
        }

        updateUserBalance(logged_user, -amount);
        updateUserBalance(dest, amount);
        
        addTransaction(transactionID, logged_user, dest, -amount ,currentTimestamp);
        addTransaction(transactionID, dest, logged_user, amount ,currentTimestamp);

        response_pkt.responseCode = 200;
        response_pkt.timestamp = rcv_pkt.timestamp;   
        response_pkt.responseContent = "OK";   

        return response_pkt.serializePacket();

    }catch(...){
        return response_pkt.serializePacket();
    }

}


// Send to requesting user the History of the transactions performed
string history(client_info rcv_pkt, string logged_user)
{
    server_info response_pkt;
    string userHistory = getUserHistory(logged_user);
    response_pkt.responseContent = userHistory;
    response_pkt.responseCode = 200;
    response_pkt.timestamp = rcv_pkt.timestamp;
    return response_pkt.serializePacket();
}

// Logout
string logout(client_info rcv_pkt, string logged_user)
{
    // Build response packet
    server_info response_pkt;
    response_pkt.timestamp = rcv_pkt.timestamp;
    response_pkt.responseCode = 200;
    response_pkt.responseContent = "OK";
    // Serialize packet
    return response_pkt.serializePacket();
}
