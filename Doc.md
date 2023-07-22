# 1 Introduzione
Il progetto ha lo scopo di creare un'applicazione client-server in C++ per la gestione del proprio home banking. L'applicazione prevede l'utilizzo di particolari accortezze legate alla sicurezza. In particolare assicura confidenzialità, integrità, non-malleabilità e no-replay attack vulnerabilities.
L'applicazione permette di effettuare operazioni molto semplici come la possibilità di controllare il proprio bilancio, effettuare trasferimento di denaro ad un altro utente e infine offre la possibilità di avere una lista di trasferimenti effettuati.
Ogni utente possiede una coppia di chiavi private e pubbliche e lo stesso il server. Il client possiede la chiave pubblica del server mentre il server contiene le chiavi pubbliche di tutti gli utenti.

# 1.1. Server
Il server è stato implementato senza utilizzare tecniche di multithreading in quanto è pensato per avere un solo utente connesso per volta che una volta terminate le proprie operazioni effettua il logout e permette a nuovi utenti di connettersi.

# 1.2. Client 
Il client ha una struttura molto semplice. Permette infatti all'utente di effettuare il login con le proprie credenziali e una volta effettuato l'accesso permette di effettuare le operazioni citate in precedenza andando a contattare il serveer.

# 2. File Structure
Il server mantiene un file users contenente username, hash della password e userID. E' il file che viene consultato per verificare se l'utente è effettivamente registrato al sistema bancario.
Per ogni utente poi vengono mantenuti due file:
- userHistory: contiene la lista delle transazioni effettuate dall'utente user. Ogni riga del file contiene: transactionID, destUsername, amount and timestamp.
- userBalance: contiene il balance dell'utente user. Ha una struttura del tipo: userID, balance.

Ogni file è cifrato utilizzando digital envelope.

# 3. Protocol
Inizialmente sono state create le chiavi pubbliche e private di server e utenti. 
Per quanto riguarda il protocollo di autenticazione è stato utilizzato il protocollo Station-To-Station per stabilire le chiave simmetriche di cifratura. In particolare tra client e server vengono stabilite due chiavi utilizzando Diffie-Helmann, denominare symmetricKey e hmacKey. La prima viene utilizzata per cifrare il contenuto dei messaggi mentre la seconda viene usata per generare l'hash del pacchetto così da assicurare la non-malleabilità. Using this protocol, we have PFS (Perfect Forward Secrecy) and DA (Direct authentication). 
Il protocollo utilizzato prevede poi che prima di inviare un pacchetto effettivo si invia un pacchetto contenente la dimensione del pacchetto che sta per arrivare per evitare di avere problemi dovuti ad esempio a buffer overflow.

# 3.1. Authentication Protocol
IMG

# 3.1.1. Packet Structure
# 3.1.2. HELLO Pkt
Il primo pacchetto che viene mandato dal client è l'HELLO pkt.

- Code: Specifica il tipo di pacchetto (HELLO in questo caso).
- usernameLen: Indica la dimensione dell'username.
- username: Username.
- symmetricKeyLen: Indica la dimensione del parametro di DH per la chiave simmetrica.
- symmetricKey: Indica il parametro di DH per la chiave simmetrica.
- hmacKeyLen: Indica la dimensione del parametro di DH per la chiave utilizzata per l'hashing.
- hmacKey: Indica il parametro di DH per la chiave utilizzata per l'hashing.

# 3.1.3. Authentication Pkt

- symmetricKeyLen: Indica la dimensione del parametro di DH per la chiave simmetrica.
- symmetricKey: Indica il parametro di DH per la chiave simmetrica.
- hmacKeyLen: Indica la dimensione del parametro di DH per la chiave utilizzata per l'hashing.
- hmacKey: Indica il parametro di DH per la chiave utilizzata per l'hashing.
- iv: Indica l'Initialization Vector utilizzato per la cifratura.
- signatureLen: Indica la dimensione della firma digitale.
- signature: Indica la firma digitale.

# 3.2. Communication Protocol
IMG

# 3.2.1. Packet Structure
Il pacchetto di comunicazione generico ha la seguente struttura:

IMG

- iv: Initialization Vector utilizzato per cifrare il contenuto del pacchetto.
- cipherLen: Dimensioni del contenuto cifrato del pacchetto.
- cipherText: Contenuto del pacchetto cifrato.
- HMAC: Hash ottenuto a partire dal contenuto in chiaro del pacchetto.

Il contenuto del pacchetto ha poi una struttura diversa se si tratta di un pacchetto proveniente dal server o del client.

# 3.2.2. clientInfo
Se il pacchetto viene dal client, il contenuto in chiaro ha la seguente struttura:

IMG

- operationCode: Indica quale operazione si vuole effettuare (balance, history, transfer, logout).
- timestamp: Indica il timestamp utilizzato per la freshness della comunicazione.
- destAndAmount: In caso di operazione di transfer contiene l'username del destinatario e l'importo, formattati nella maniera "username-amount"

I campi sono separati dal carattere "|", questo aiuta in fase di serializzazione/deseralizzazione.

# 3.2.3. serverInfo
Se il pacchetto viene dal client, il contenuto in chiaro ha la seguente struttura:

IMG

- responseCode: Indica un codice di risposta, ispirato ad HTTP (200,500)
- timestamp: Indica il timestamp utilizzato per la freshness della comunicazione.
- responseContent: Contiene effettivamente il risultato della richiesta, come il balance, la history o un messaggio di errore.

I campi sono separati dal carattere "|", questo aiuta in fase di serializzazione/deseralizzazione.

