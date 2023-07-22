#include "./utils.cpp"
#include <string.h>

// Returns the balance to the user
string balance(clientInfo rcvPkt, string loggedUser)
{
    serverInfo response_pkt;
    string balance = getBalanceAndUserID(loggedUser);
    if (balance == ""){
        response_pkt.responseCode = 500;
        response_pkt.responseContent = "Balance Error.";
    }else{
        response_pkt.responseCode = 200;
        response_pkt.responseContent = balance;
    }
    response_pkt.timestamp = rcvPkt.timestamp;
    
    // Serialize packet
    return response_pkt.serializePacket();
}



// Transfer an amount of money to another user
string transfer(clientInfo rcvPkt, string loggedUser)
{
    // Build response pkt
    serverInfo response_pkt;
    string dest;
    int amount;
    string s = rcvPkt.destAndAmount;
    string delimiter = "-";
    unsigned int pos;

    pos = s.find(delimiter, 0);
    dest = s.substr(0 , pos);
    amount = stoi(s.substr(pos + 1));

    try{
        // check if the username is valid
        if(!checkUsername(dest)){
            cerr << "[ERROR] Receiver doesn't exist." << endl;
            response_pkt.responseCode = 500;
            response_pkt.responseContent = "Invalid dest";
            throw exception();
        }

        int senderBalance = stoi(getBalanceAndUserID(loggedUser));
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

        updateUserBalance(loggedUser, -amount);
        updateUserBalance(dest, amount);
        
        addTransaction(transactionID, loggedUser, dest, -amount ,currentTimestamp);
        addTransaction(transactionID, dest, loggedUser, amount ,currentTimestamp);

        response_pkt.responseCode = 200;
        response_pkt.timestamp = rcvPkt.timestamp;   
        response_pkt.responseContent = "OK";   

        return response_pkt.serializePacket();

    }catch(...){
        return response_pkt.serializePacket();
    }

}


// Send to requesting user the History of the transactions performed
string history(clientInfo rcvPkt, string loggedUser)
{
    serverInfo response_pkt;
    string userHistory = getUserHistory(loggedUser);
    response_pkt.responseContent = userHistory;
    response_pkt.responseCode = 200;
    response_pkt.timestamp = rcvPkt.timestamp;
    return response_pkt.serializePacket();
}

// Logout
string logout(clientInfo rcvPkt, string loggedUser)
{
    // Build response packet
    serverInfo response_pkt;
    response_pkt.timestamp = rcvPkt.timestamp;
    response_pkt.responseCode = 200;
    response_pkt.responseContent = "OK";
    // Serialize packet
    return response_pkt.serializePacket();
}
