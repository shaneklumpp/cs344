/*Shane Klumpp Project 4 otp_dec_d.c file. Uses the server.c file as a starting place.
decrypts cyphertext and returns plaintext

*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

#define CIPHER_TEXT_MAX_SIZE 70005
#define KEY_TEXT_MAX_SIZE	70005

//prototypes
void printBuffer(char Buffer[], int size);
void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues
static void handleChildren(int sig); //SIGCHLD handler to reap dead child processes
static void handleRequest(int cfd); //handle a client request function
void remapText(char* buffer, int bufferSize); //remaps ' ' -> '[' for easier modular addition with ascii characters. Also frame shifts by - 'A'
void createCipher(char* cipher, const char* plainText, const char* key, int ); //creates cipherText by adding plainText + Key, % 27, then frame shifting + 'A' not used in otp_dec just for testing
void decryptCipher(char* decryptText, const char* cipherText, const char* key, int charsToDecrypt); //decrypts text in otp_dec_d
size_t writeToFD(int FD, const char* bufferToWrite, size_t n); //same as in otp_enc
ssize_t readFromFD(int FD, void* bufferReadIn, size_t numberToRead); //same as in otp_enc

int main(int argc, char *argv[])
{
	int listenSocketFD, establishedConnectionFD, portNumber, charsRead;
	socklen_t sizeOfClientInfo;
	char buffer[256];
	struct sockaddr_in serverAddress, clientAddress;
	
	//set up sigaction handler for child processes
	struct sigaction sa;
	
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = handleChildren;		//use handleChildren function
	sigaction(SIGCHLD, &sa, NULL);	//setup SIGCHLD
	
	if (argc < 2) { fprintf(stderr,"USAGE: %s port\n", argv[0]); exit(3); } // Check usage & args

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (listenSocketFD < 0) {
		error("ERROR opening socket");
		exit(1); //exit bad socket
	}

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0){ // Connect socket to port
		error("ERROR on binding");
		exit(1); //exit because bad binding
	}
	listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

	while(1){ //multiserver while loop

		// Accept a connection, blocking if one is not available until one connects
		sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
		establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
		if (establishedConnectionFD < 0) error("ERROR on accept");
		//printf("SERVER: Connected Cleint at port %d\n", ntohs(clientAddress.sin_port));
		
		//fork off a child process to handle request from client
		
		switch(fork()){ //referenced Linux Programming Interface pages 1244-45 for this section
			//error
			case -1:
				perror("Hull Breach!"); //hull breach
				close(establishedConnectionFD); //give up on this child process. Close its connection
				break; //don't exit. Try next client
			//child
			case 0:
				close(listenSocketFD); //unneeded copy of listening socket so close since children get copys of FD's
				handleRequest(establishedConnectionFD); //pass connection to handleRequest to decrypt
				exit(0);	//success exit
				break; //Including break to be safe
			//parent
			default:
				close(establishedConnectionFD); //unneeded copy of connected socket
				break; //loop to accept next connection
			
		} //end fork() switch
		
	} //end while loop
	
	close(listenSocketFD); // Close the listening socket done
	return 0; 
}

void printBuffer(char Buffer[], int size){ //testing buffers
	int i;
	for(i = 0; i < size; i++){
		printf("%c  =>  %d\n",Buffer[i], Buffer[i]);
	}
	
}

//cleaup child processes
//referenced Linux Programming Interface pages 1244-45 for this section
static void handleChildren(int sig){

	//catch children so they don't zombiefy using WNOHANG and -1 for any children!
	while (waitpid(-1, NULL, WNOHANG) > 0){ //wait for any children to be complete in an infinite loop without suspending execution
		//printf("A child died!\n");
		continue;
	}

}

//handle client requests. Does all the processing from the client depending on otp enc d or otp dec d
static void handleRequest(int establishedConnectionFD){
	char buffer[256];
	int charsRead;
	int confirmationValue; //check confirmation value using strcmp. If not 0 send back error to client to terminate itself
	
	fd_set readFDs;				//readFD's for select()
	struct timeval timeToWait;	//timeToWait
	int retval;					//return value for select()
	
	FD_ZERO(&readFDs);									//zero readFile Descriptor
	FD_SET(establishedConnectionFD, &readFDs);			//client listens on socketFD for recieving messages and sending but we only care about recieving for select
	
	timeToWait.tv_sec = 4; //wait for 4 seconds maximum
	timeToWait.tv_usec = 0; //zero microseconds
	
	
	/****************************************************
	 *1) get confirmation message from the client. Expecting message "decoder" only
	****************************************************/
	memset(buffer, '\0', 256);
	charsRead = recv(establishedConnectionFD, buffer, 255, 0); // Read the client's message from the socket
	if (charsRead < 0) error("ERROR reading from socket");
	//printf("SERVER: I received this from the client: \"%s\"\n", buffer);
	
	confirmationValue = strcmp(buffer, "decoder");
	//printf("The confirmationValue is: %d\n", confirmationValue);
	
	if(confirmationValue != 0){
		charsRead = send(establishedConnectionFD, "terminate", 10 , 0); //send terminate signal to client who isn't a decoder
		if (charsRead < 0) error("ERROR writing to socket");
		exit(0); //exit as there won't be anything coming in from that client again as it terminates
	}
	else{
		charsRead = send(establishedConnectionFD, "continue", 10, 0);
		if (charsRead < 0) error("ERROR writing to socket");
	}
	
	/*************************************************************************************
	//2) handle cipherText being sent from otp_enc
	*************************************************************************************/
	int cipherTextRecvSize = 0; //holds how large the cipherText is going to be in byte size
	size_t cipherTextExpectedSize; //holds expected size
	int return_status = 0;
	while(return_status <= 0){ //small integer value so just read until its read without read function
		return_status = read(establishedConnectionFD, &cipherTextRecvSize, sizeof(cipherTextRecvSize));
		if(return_status > 0){
			//printf("Return status: %d\n", return_status);
			//printf("Recieved cipherTextSize int = %d\n", ntohl(cipherTextRecvSize));
			cipherTextExpectedSize = ntohl(cipherTextRecvSize);
			//printf("Checking cipherTextExpectedSize size_t, should match value above: %zu\n", cipherTextExpectedSize);
		}
	}
	
	//watch establishedConnectionFD for reading cipherText. Don't care about writing/error. Wait 4 seconds
	retval = select(establishedConnectionFD + 1, &readFDs, NULL, NULL, &timeToWait); 
	
	char cipherTextRecv[CIPHER_TEXT_MAX_SIZE]; //allocate 70000 byte buffer for maximum cipherText size
	memset(cipherTextRecv, '\0', CIPHER_TEXT_MAX_SIZE); //null terminator out
	
	if(retval == -1){
		perror("select()");
	}
	else if (retval) { //can be read now
		
		//printf("SERVER: select() returned. cipherTextRecv can be read now\n");
		//printf("SERVER: checking FD int establishedConnectionFD: %d\n", establishedConnectionFD);
		
		//recieve cipher text into cipherTextRecv
		size_t cipherTextTry;
		//int counter = 0;
		do{
			cipherTextTry = 0;
			cipherTextTry = readFromFD(establishedConnectionFD, cipherTextRecv, cipherTextExpectedSize);
			//fprintf(stderr, "SERVER: cipherTextTry = %zu\n", cipherTextTry);
			
			//counter++;
			//if(counter == 2){ break;} //testing purposes
			
		} while(cipherTextTry != (size_t) cipherTextExpectedSize); //until it matches expected size rerun
		

	}
	else{
		printf("No data within 4 seconds\n");
	}
	//cipherText recieved
	// Send a Success message back to the client to clear up traffic
	charsRead = send(establishedConnectionFD, "SERVER: cipherText recieved", 27, 0); // Send success back
	if (charsRead < 0) error("ERROR writing to socket");
	
	
	/************************
	 * 3) Handle Key from client
	************************/
	
	int keyRecvSize = 0; //holds how large the keyText is going to be in byte size
	size_t keyExpectedSize; //expected size
	return_status = 0;
	while(return_status <= 0){
		return_status = read(establishedConnectionFD, &keyRecvSize, sizeof(keyRecvSize));
		if(return_status > 0){
			//printf("Return status: %d\n", return_status);
			//printf("Recieved keySize int = %d\n", ntohl(keyRecvSize));
			keyExpectedSize = ntohl(keyRecvSize);
			//printf("Checking keyExpectedSize size_t, should match value above: %zu\n", keyExpectedSize);
		}
	}
	
	//watch establishedConnectionFD for reading key. Don't care about writing/error. Wait 4 seconds
	retval = select(establishedConnectionFD + 1, &readFDs, NULL, NULL, &timeToWait); 
	
	char keyTextRecv[KEY_TEXT_MAX_SIZE]; //allocate 70000 byte buffer for maximum key size
	memset(keyTextRecv, '\0', KEY_TEXT_MAX_SIZE); //null terminator out
	
	if(retval == -1){
		perror("select()");
	}
	else if (retval) { //can be read now
	
		//printf("SERVER: select() returned. keyTextRecv can be read now\n");
		//printf("SERVER: checking FD int establishedConnectionFD: %d\n", establishedConnectionFD);
		
		//recieve cipher text into cipherTextRecv
		size_t keyTextTry;
		//int counter = 0;
		do{
			keyTextTry = 0;
			keyTextTry = readFromFD(establishedConnectionFD, keyTextRecv, keyExpectedSize);
			//fprintf(stderr, "keyTextTry = %zu\n", keyTextTry);
			
			//counter++;
			//if(counter == 2){ break;}
			
		} while(keyTextTry != (size_t) keyExpectedSize); //read until expected size is reached
		
	}
	else{
		printf("No data within 4 seconds\n");
	}
	
	
	//key recieved
	// Send a Success message back to the client to clear up traffic
	charsRead = send(establishedConnectionFD, "SERVER: Key Recieved", 21, 0); // Send success back
	if (charsRead < 0) error("ERROR writing to socket");
	
	
	/*************************
	 * 4) Remap cipherText and Key from ' ' -> '['
	 * 5) Use cipherText and Key to create decipherText and send back to client
	**************************/
	
	char* cipherTextRemap = malloc(strlen(cipherTextRecv)*sizeof(char));	//allocate space for cipherTextRemap
	strcpy(cipherTextRemap, cipherTextRecv);								//copy cipherTextRecv -> cipherTextRemap so it doesn't get screwed up
	int cipherTextRemapLength = strlen(cipherTextRemap);					//get length of cipherTextRemap for testing
	//printf("cipherTextRemap on nextline before remaping\n");
	//printf("%s\n", cipherTextRemap);
	remapText(cipherTextRemap, strlen(cipherTextRemap));					//' ' - > '[' and frameshift -'A'
	//printf("cipherTextRemap on nextline after remaping\n");
	//printf("%s\n", cipherTextRemap);
	
	char* keyRemap = malloc(strlen(keyTextRecv)*sizeof(char));			//same notes as above
	strcpy(keyRemap, keyTextRecv);
	int keyRemapLength = strlen(keyRemap);
	//printf("keyRemap on nextline before remaping\n");
	//printf("%s\n", keyRemap);
	remapText(keyRemap, strlen(keyRemap));
	//printf("keyRemap on nextline after remaping\n");
	//printf("%s\n", keyRemap);
	
	/* //TESTING
	printf("Checking ascii chars of cipherTextRemap\n");
	printBuffer(cipherTextRemap, cipherTextRemapLength); //can't use strlen(cipherTextRemap) as that contains early '\0' as its been frame shifted 
	printf("\nChecking ascii chars of keyRemap\n");
	printBuffer(keyRemap, keyRemapLength); //same reason as above
	*/
	
	//5) Create decipherText using remaped cipherText and key
	//!! Must use cipherTextRemapLength here as cipherTextRemap contains '\0' characters now!!!
	char* decipherText = malloc((cipherTextRemapLength + 1)*sizeof(char)); //+1 for \0
	memset(decipherText, '\0', cipherTextRemapLength + 1);
	
	int charsToDecipher = cipherTextRemapLength; //need to convert all chars within cipherTextRemap up to the \0. But cipherTextRemap contains extraneous \0 chars so use cipherTextRemapLength
	
		
	decryptCipher(decipherText, cipherTextRemap, keyRemap, charsToDecipher);
	
	//printf("decryptText below\n");
	//printf("%s\n", decipherText);
	//printBuffer(decipherText, strlen(decipherText) + 1); //check characters converted and null terminator is there
	
	
	size_t decipherTextLength = strlen(decipherText);
	
	//recieve ready text
	memset(buffer, '\0', 256);
	charsRead = recv(establishedConnectionFD, buffer, 255, 0); // Read the client's message from the socket
	if (charsRead < 0) error("ERROR reading from socket");
	//printf("SERVER: I received this from the client: \"%s\"\n", buffer);
	

	//send decipherText using writeToFD function because the message can be very long (70000 bytes max) and may be interupted
	size_t decipherTextTry;
	do{
		decipherTextTry = 0;
		decipherTextTry = writeToFD(establishedConnectionFD, decipherText, strlen(decipherText));
		//printf("decipherTextTry sending = %zu\n", decipherTextTry);
		
	} while ((decipherTextTry != (size_t) decipherTextLength)); //send until whole buffer is sent
	
	
} //END HANDLING CLIENT

//remaps first by converting ' ' to '['
//then frameshifts by subtracting 'A' which should make the ascii value 0-27 as 'A' - 'A' = 0 and '[' - 'A' = 26
void remapText(char* buffer, int bufferSize){
	int i; //iterator
	for(i = 0; i < bufferSize; i++){
		if(buffer[i] == ' '){
			buffer[i] = '['; //remap from space to '['
		}
	}
	//printf("Remaped Text before frame shifting below:\n");
	//printf("%s\n", buffer);
	for(i = 0; i< bufferSize; i++){
		buffer[i] -= 'A'; //frameshift subtract 'A' to get ascii value of 0-26
	}
}

//doesn't do anything in otp_dec_d but left in for simplicity. Never called in child handler
void createCipher(char* cipher, const char* plainText, const char* key, int charsToConvert){
	int i; //iterator
	int current; //holder that does addition, modulation, and frame shifting before adding to cipher[i]
	
	for(i = 0; i < charsToConvert; i++){
		current = 0;
		current = plainText[i] + key[i]; //add ascii character values together
		//printf("Adding plainText[i] ascii: %d to key[i] ascii: %d\n", plainText[i], key[i]);
		//printf("After adding plainText and key current: %d\n", current);
		current = current % 27; //modulate total ascii by 27
		//printf("After modulation current: %d\n", current);
		current += 'A'; //frame shift back by adding 'A' ascii value
		//printf("After adding 'A' current: %d\n", current);
		cipher[i] = current; //add back into cipher[i];
		//printf("cipher[i] char %c and ascii %d\n", cipher[i], cipher[i]);
	}
	//done frame shifting back. Now to adjust for '[' values
	for(i = 0; i < charsToConvert; i++){
		if(cipher[i] == '['){
			cipher[i] = ' '; //adjust back to space
		}
	}
	
	//done creating cipher text
}


//takes in remaped cipherText and remaped keys that have their ' ' -> '[' and ascii values subtracted - 'A' to be ascii 0-26
//uses modular subtraction: cipherText - key value. If below 0 add 27
//frame shifts back by adding 'A' to that value
//Then goes thru decypherText and converted '[' -> ' '
void decryptCipher(char* decryptText, const char* cipherText, const char* key, int charsToDecrypt){
	int i; //iterator
	int current; //holder that does the arithmetic work on it before storing in decryptText[i]
	
	for(i = 0; i < charsToDecrypt; i++){
		current = 0;
		current = cipherText[i] - key[i]; //modular subtraction
		if(current < 0){
			current += 27; //add 26 if below 0
		}
		current += 'A'; //frame shift back to 65-91 ascii value
		decryptText[i] = current; //put into decryptText c string
	}
	//done with decryption and frame shifting. '[' -> ' '
	for(i = 0; i < charsToDecrypt; i++){
		if(decryptText[i] == '['){
			decryptText[i] = ' '; //put back as a space
		}
	}// done with spaces
	//done decrypting
}


//same as in otp_dec but used for the same purpose in otp_dec_d
//Reads from file descriptor passed in from function call. Uses bufferToWrite and numberToWrite to send to client/server
//will run until totalWritten bytes == numberToWrite bytes that is passed in. Should be run in a while loop above to make sure it returns the right amount of bytes
//uses bufPointer to point to bufferToWrite for ease of reading for later use
//counts number of bytes written and returns to function call. Should be run in a while loop if actual sent != expected sent
size_t writeToFD(int FD, const char* bufferToWrite, size_t numberToWrite){
	size_t numberWritten = 0; //number of bytes written so far
	size_t totalWritten = 0; //total number of bytes written
	const char* bufPointer; //pointer to bufferToWrite
	
	bufPointer = bufferToWrite; //point to buffer to write
	
	while(totalWritten < numberToWrite){ //write until totalWriten is n
		numberWritten = send(FD, bufPointer, numberToWrite-totalWritten, 0); //try sending as many bytes as possible
		//printf("numberWritten after write call: %zu\n", numberWritten);
		
		if(numberWritten <= 0){ //interruption
			if(numberWritten == -1){
				continue; //there was a network interuption causing -1 error. restart the send call
			}
			else{
				return -1; //there was another error. Restart the entire writeToFD call by returning -1 and trying again
			}
			
		}
		// no errors so update totalWritten and the buffer pointer here
		totalWritten += numberWritten; //update the total bytes written
		//printf("totalWritten = %zu\n", totalWritten);
		bufPointer += numberWritten; //update the buffer pointer so we aren't sending repeat bytes
	}
	return totalWritten; //reaching this means totalWritten = n which is the total amount of data needed to be sent. Check in function call above within a while loop to ensure
}

//Similar functionality to writeToFD
//read from FD into bufferReadIn, with the numberToWrite as the expected number of bytes to read In
//try recv'ing all bytes in FD until reaching numberToRead
//check in main against number of expected bytes, rerun if not the exact same
ssize_t readFromFD(int FD, void* bufferReadIn, size_t numberToRead){
	size_t numberRead = 0; //number read since last recv
	size_t totalRead = 0; //total bytes read, returned to calling function and compared against expected bytes to read
	char* bufPointer; //pointer to bufferReadIn to know where to write bytes into
	bufPointer = bufferReadIn; //point to read in buffer
	
	/*
	 //Testing printfs
	printf("FD int = %d\n", FD);
	printf("SERVER: I am in the readFromFD() function \n");
	printf("passed numberToRead = %zu\n", numberToRead);
	printf("numberToRead - totalRead = %zu\n", numberToRead-totalRead);
	*/
	
	while(totalRead < numberToRead){ //try writing up to the point of numberToWrite
		numberRead = recv(FD, bufPointer, numberToRead - totalRead, 0); //read bytes left to read into bufPointer -> bufferReadIn
		
		//printf("SERVER: numberRead from within readFromFD while loop: %zu\n", numberRead);
		//fprintf(stderr, "SERVER: numberRead from within readFromFD while loop: %zu\n", numberRead);
		
		
		if(numberRead == 0){
			return totalRead; //nothing left to read return total or error condition. totalRead must be checked anyways
		}
		else if(numberRead == -1){ //error from recv
			return -1; //error condition restart entire read
		}
		totalRead += numberRead; //update totalRead on this recv call
		bufPointer += numberRead; //update read location to read into so bytes aren't overwritten using current numberRead position
	}
	return totalRead; //return totalRead and compare against expected value. Retry recv if not the exact same
	
}