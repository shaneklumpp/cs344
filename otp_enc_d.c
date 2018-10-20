/*Shane Klumpp Project 4 otp_enc_d.c file. Uses the server.c file as a starting place.
encrypts cypher text and returns to otp enc

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

#define PLAIN_TEXT_MAX_SIZE 70005
#define KEY_TEXT_MAX_SIZE	70005

//prototypes
void printBuffer(char Buffer[], int size);
void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues
static void handleChildren(int sig); //SIGCHLD handler to reap dead child processes
static void handleRequest(int cfd); //handle a client request function
void remapText(char* buffer, int bufferSize); //remaps ' ' -> '[' for easier modular addition with ascii characters. Also frame shifts by - 'A'
void createCipher(char* cipher, const char* plainText, const char* key, int ); //creates cipherText by adding plainText + Key, % 27, then frame shifting + 'A'
void decryptCipher(char* decryptText, const char* cipherText, const char* key, int charsToDecrypt); //decrypts text used for testing in otp_enc_d. Gets the decrypted text
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
				handleRequest(establishedConnectionFD); //pass connection to handleRequest to encrypt
				exit(0);	//success exit
				break; //Including break to be safe
			//parent
			default:
				close(establishedConnectionFD); //unneeded copy of connected socket
				break; //loop to accept next connection
			
		} //end fork() switch
		
	} //end while loop
	
	close(listenSocketFD); // Close the listening socket
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
	 *1) get confirmation message from the client. Expecting message "encoder" only
	****************************************************/
	memset(buffer, '\0', 256);
	charsRead = recv(establishedConnectionFD, buffer, 255, 0); // Read the client's message from the socket
	if (charsRead < 0) error("ERROR reading from socket");
	//printf("SERVER: I received this from the client: \"%s\"\n", buffer);
	
	confirmationValue = strcmp(buffer, "encoder");
	//printf("The confirmationValue is: %d\n", confirmationValue);
	
	if(confirmationValue != 0){
		charsRead = send(establishedConnectionFD, "terminate", 10 , 0); //send terminate signal to client who isn't an encoder
		if (charsRead < 0) error("ERROR writing to socket");
		exit(0); //exit as there won't be anything coming in from that client again as it terminates
	}
	else{
		charsRead = send(establishedConnectionFD, "continue", 10, 0);
		if (charsRead < 0) error("ERROR writing to socket");
	}
	
	/*************************************************************************************
	//2) handle plaintext being sent from otp_enc
	*************************************************************************************/
	int plainTextRecvSize = 0; //holds how large the plainText is going to be in byte size
	size_t plainTextExpectedSize; //holds expected size
	int return_status = 0;
	while(return_status <= 0){ //small integer value so just read until its read without read function
		return_status = read(establishedConnectionFD, &plainTextRecvSize, sizeof(plainTextRecvSize));
		if(return_status > 0){
			//printf("Return status: %d\n", return_status);
			//printf("Recieved plainTextSize int = %d\n", ntohl(plainTextRecvSize));
			plainTextExpectedSize = ntohl(plainTextRecvSize);
			//printf("Checking plainTextExpectedSize size_t, should match value above: %zu\n", plainTextExpectedSize);
		}
	}
	
	//watch establishedConnectionFD for reading plainText. Don't care about writing/error. Wait 4 seconds
	retval = select(establishedConnectionFD + 1, &readFDs, NULL, NULL, &timeToWait); 
	
	char plainTextRecv[PLAIN_TEXT_MAX_SIZE]; //allocate 70000 byte buffer for maximum plaintext size
	memset(plainTextRecv, '\0', PLAIN_TEXT_MAX_SIZE); //null terminator out
	
	if(retval == -1){
		perror("select()");
	}
	else if (retval) { //can be read now
		
		//printf("SERVER: select() returned. plainTextRecv can be read now\n");
		//printf("SERVER: checking FD int establishedConnectionFD: %d\n", establishedConnectionFD);
		
		//recieve cipher text into cipherTextRecv
		size_t plainTextTry;
		//int counter = 0;
		do{
			plainTextTry = 0;
			plainTextTry = readFromFD(establishedConnectionFD, plainTextRecv, plainTextExpectedSize);
			//fprintf(stderr, "plainTextTry = %zu\n", plainTextTry);
			
			//counter++;
			//if(counter == 2){ break;}
			
		} while(plainTextTry != (size_t) plainTextExpectedSize); //until it matches expected size rerun
		
	}
	else{
		printf("No data within 4 seconds\n");
	}
	//plaintext recieved
	// Send a Success message back to the client to clear up traffic
	charsRead = send(establishedConnectionFD, "SERVER: plainText recieved", 27, 0); // Send success back
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
	
	char keyTextRecv[KEY_TEXT_MAX_SIZE]; //allocate 70000 byte buffer for maximum plaintext size
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
	 * 4) Remap plainText and Key from ' ' -> '['
	 * 5) Use plainText and Key to create CipherText and send back to client
	**************************/
	
	char* plainTextRemap = malloc(strlen(plainTextRecv)*sizeof(char));	//allocate space for plainTextRemap
	strcpy(plainTextRemap, plainTextRecv);								//copy plainTextRecv -> plainTextRemap so it doesn't get screwed up
	int plainTextRemapLength = strlen(plainTextRemap);					//get length of plainTextRemap for testing
	//printf("plainTextRemap on nextline before remaping\n");
	//printf("%s\n", plainTextRemap);
	remapText(plainTextRemap, strlen(plainTextRemap));					//' ' - > '[' and frameshift -'A'
	//printf("plainTextRemap on nextline after remaping\n");
	//printf("%s\n", plainTextRemap);
	
	char* keyRemap = malloc(strlen(keyTextRecv)*sizeof(char));			//same notes as above
	strcpy(keyRemap, keyTextRecv);
	int keyRemapLength = strlen(keyRemap);
	//printf("keyRemap on nextline before remaping\n");
	//printf("%s\n", keyRemap);
	remapText(keyRemap, strlen(keyRemap));
	//printf("keyRemap on nextline after remaping\n");
	//printf("%s\n", keyRemap);
	
	/* //TESTING
	printf("Checking ascii chars of plainTextRemap\n");
	printBuffer(plainTextRemap, plainTextRemapLength); //can't use strlen(plainTextRemap) as that contains early '\0' as its been frame shifted 
	printf("\nChecking ascii chars of keyRemap\n");
	printBuffer(keyRemap, keyRemapLength); //same reason as above
	*/
	
	//5) Create cipherText using remaped plaintext and key
	//!! Must use plainTextRemapLength here as plainTextRemap contains '\0' characters now!!!
	char* cipherText = malloc((plainTextRemapLength + 1)*sizeof(char)); //+1 for \0
	memset(cipherText, '\0', plainTextRemapLength + 1);
	
	int charsToConvert = plainTextRemapLength; //need to convert all chars within plainTextRemap up to the \0. But plainTextRemap contains extraneous \0 chars so use plainTextRemapLength
	
	createCipher(cipherText, plainTextRemap, keyRemap, charsToConvert); //create cipher text and put it into cipherText
	
	int cipherTextLength = strlen(cipherText); 
	
	//printf("cipherText below\n");
	//printf("%s\n", cipherText);
	//printBuffer(cipherText, strlen(cipherText) + 1); //check characters converted and null terminator is there
	//printf("cipherText length: %zu\n", strlen(cipherText));
	
	
	//done creating cipherText that has been modulated with addition and converted to cipher text ready to send
	
	
	//recieve ready text
	memset(buffer, '\0', 256);
	charsRead = recv(establishedConnectionFD, buffer, 255, 0); // Read the client's message from the socket
	if (charsRead < 0) error("ERROR reading from socket");
	//printf("SERVER: I received this from the client: \"%s\"\n", buffer);
	

	//send cipherText using writeToFD function because the message can be very long (70000 bytes max) and may be interupted
	size_t cipherTextTry;
	do{
		cipherTextTry = 0;
		cipherTextTry = writeToFD(establishedConnectionFD, cipherText, strlen(cipherText));
		//printf("cipherTextTry sending = %zu\n", cipherTextTry);
		
	} while ((cipherTextTry != (size_t) cipherTextLength)); //send until whole buffer is sent
	
	
	/***************
	//Testing by decrypting the cipherText above for us in otp_dec and otp_dec_d just to doing it now so I know it works
	//THIS DOESN'T DO ANYTHING SINCE IT IS COMMMENTED OUT I LEFT IT IN FOR COPY PASTING LATER!
	****************/
	
	/*
	 //commenting out for later copy pasting
	
	char* remapCipher = malloc(strlen(cipherText)*sizeof(char));
	memset(remapCipher, '\0', strlen(cipherText+1));
	strcpy(remapCipher, cipherText);
	//printf("remapCipher on nextline before remaping\n");
	//printf("%s\n", remapCipher);
	remapText(remapCipher, strlen(remapCipher));
	//printf("remapCipher on nextline after remaping\n");
	//printf("%s\n", remapCipher);
	
	char* decipherText = malloc(strlen(cipherText)*sizeof(char));
	memset(decipherText, '\0', sizeof(decipherText)); //memset to null terminators
	
	int charsToDecipher = strlen(cipherText);
	
	decryptCipher(decipherText, remapCipher, keyRemap, charsToDecipher);
	
	printf("decryptText below\n");
	printf("%s\n", decipherText);
	//printBuffer(decipherText, strlen(decipherText) + 1); //check characters converted and null terminator is there
	*/
	
	
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


//creates cipher text using modular addition for sending to client. comments explain function
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


/**********************
 * I WANT TO MAKE IT VERY VERY VERY VERY CLEAR THAT OTP_ENC_D DOESN'T USE THIS IN ACTUAL RUN TIME
 * THIS IS JUST FOR TESTING PURPOSES I WROTE DECRYPT CYPHER BEFORE MOVING ONTO OTP_DEC!!!!!!!!
 * 
**********************/
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


//same as in otp_enc but used for the same purpose in otp_enc_d
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