#include "./../utils/env.h"
#include <string.h>

// Checks if the username is present into the DB
bool checkUsername(string username)
{
    if (username.find_first_not_of(USERNAME_WHITELIST_CHARS) != std::string::npos)
        return false;
    unsigned char *allUsers = decryptFile("./src/server/files/users.txt.enc");
    string userList((char *)allUsers);
    free(allUsers);
    string lineDelimiter = "\n";
    string usernameLimiter = " ";
    unsigned int delimiterPos = 0;
    unsigned int pos = 0;
    unsigned int endLinePos =  0;

    while (pos <= userList.length())
    {
        delimiterPos = userList.find(usernameLimiter, pos);
        string name = userList.substr(pos, delimiterPos - pos);
        if (name.compare(username) == 0)
        {
            return true;
        }
        unsigned int endLinePos = userList.find(lineDelimiter, pos);
        pos = pos + endLinePos + 1;
    }
    return false;
}

string generateID(){
    int idSize = 8;
    unsigned char * id = (unsigned char *)malloc(idSize);
    string stringID;

    if (RAND_bytes((unsigned char*)id, idSize) != 1) {
        cerr << "[ERROR] Impossible generate ID" << endl;
        return "";
    }

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < idSize; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(id[i]);
    }
    string saltHex = oss.str();
    free(id);
    return saltHex;
}

string getBalanceFromFileRow(unsigned char* fileRow){
    string s = (char * )fileRow;
    string delimiter = " ";
    int pos = 0;
    int delimiterPos = 0;

    delimiterPos = s.find(delimiter , pos);
    s = s.substr(delimiterPos + 1);
    return s;
}

string getUserIDFromFileRow(unsigned char* fileRow){
    string s = (char * )fileRow;
    string delimiter = " ";
    int pos = 0;
    int delimiterPos = 0;

    delimiterPos = s.find(delimiter , pos);
    s = s.substr(pos , delimiterPos);
    return s;
}

void updateUserBalance(string user, int amount){
    unsigned char *idAndBalance = decryptFile("./src/server/files/" + user + "Balance.txt.enc");
    string userID = getUserIDFromFileRow(idAndBalance);
    int userBalance = stoi(getBalanceFromFileRow(idAndBalance));

    string newRow = userID + " " + to_string(userBalance + amount);
    encryptFile("./src/server/files/" + user + "Balance.txt.enc" , "OVERWRITE" , newRow);
}

bool fileExists(const string filename) {
    ifstream file(filename);
    return file.good();
}

void addTransaction(string transactionID, string user, string userToWrite, int amount, uint64_t timestamp){
    string filename = "./src/server/files/" + user + "History.txt.enc";
    string fileAccessMode = "APPEND";
    string fileRow;
    
    if(!fileExists(filename)){
        // create the file
        ofstream file(filename);
        file.close();
        fileAccessMode = "OVERWRITE";
        fileRow = "";
    }

    fileRow += transactionID + " " + userToWrite + " " + to_string(amount) + " " + to_string(timestamp) + "\n";
    encryptFile(filename , fileAccessMode , fileRow);

}

// Returns balance
string getBalanceAndUserID(string currentUser)
{
    if (!checkUsername(currentUser))
        return "";
    string idAndBalance = (char*)decryptFile("./src/server/files/" + currentUser + "Balance.txt.enc");
    return idAndBalance;
}


string getUserHistory(string logged_user){
    string fileName = "./src/server/files/" + logged_user + "History.txt.enc";
    unsigned char * historyContent = decryptFile(fileName);
    string content = (char *)historyContent;
    string historyResult;
    istringstream iss(content);
    string line;
    int lineCount = 0;

    while (std::getline(iss, line) && lineCount < TRANSFERS_NUM) {
        if(lineCount != 0) historyResult +="\n";
        historyResult += line;
        lineCount++;
    }
    return historyResult;
}
