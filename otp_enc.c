/*Shane Klumpp Project 4; otp_enc.c file. Uses the client.c file as a starting place.

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define CIPHER_TEXT_MAX_SIZE	70005

void error(const char *msg) { perror(msg); exit(0); } // Error function used for reporting issues

//prototypes
ssize_t readFile(char** fileText, char* fileName); //read from file into buffer
void printBuffer(char Buffer[], int size); //testing prints ascii value and chars in buffer
int checkBadChars(char Buffer[], int size); //checks bad characters in buffers
size_t writeToFD(int FD, const char* bufferToWrite, size_t n); //writes to a FD. Used for sending
ssize_t readFromFD(int FD, void* bufferReadIn, size_t numberToWrite); //reads from a FD. Used for recieving

int main(int argc, char *argv[])
{
	
	//if (argc < 3) { fprintf(stderr,"USAGE: %s hostname port\n", argv[0]); exit(0); } // Check usage & args; original
	
	if (argc < 4) {fprintf(stderr, "USAGE: %s plainTextFile keyFile port\n", argv[0]); exit(3);} //check usage and args
	
	
	int socketFD, portNumber, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
	char buffer[256];
	
	char* plainText = NULL;
	char* keyText = NULL;
	char* plainTextFile = argv[1];	//plainText File
	char* keyTextFile = argv[2];	//keyText File
    ssize_t plainTextTotalLength; //byte length
    ssize_t keyTextTotalLength; //byte length
	int plainTextLen; //actual length
	int keyTextLen;//actual length
	
	plainTextTotalLength = readFile(&plainText, plainTextFile); //read from plainText file into cipherText and get size
	plainTextLen = strlen(plainText); //get actual length
	//printf("String from plainTextFile\n");
	//printf("%s",plainText);
	//printf("Length of plainText ssize_t: %zu\n", plainTextTotalLength);
	//printf("Length of plainText int: %d\n",plainTextLen);
	//printBuffer(plainText, plainTextLength);
	
	//null terminator in place of \n char
	plainText[strcspn(plainText, "\n")] = '\0'; //\n -> \0
	//printBuffer(plainText, plainTextLength);
	plainTextLen = strlen(plainText);
	//printf("String from plainTextFile after newline to null terminator (newline added manually for readability)\n");
	//printf("%s\n",plainText);
	//printf("Length of plainText int after newline to null terminator: %d\n\n",plainTextLen);
	
	keyTextTotalLength = readFile(&keyText, keyTextFile); //get key from keytext and size
	keyTextLen = strlen(keyText);
	//printf("String from keyTextFile\n");
	//printf("%s", keyText);
	//printf("Length of keyText ssize_t: %zu\n", keyTextTotalLength);
	//printf("Length of keyText int: %d\n", keyTextLen);
	
	//null terminator in place of \n char
	keyText[strcspn(keyText, "\n")] = '\0'; //\n -> \0
	keyTextLen = strlen(keyText);
	//printf("String from keyTextFile after newline to null terminator (newline added manually for readability)\n");
	//printf("%s\n", keyText);
	//printf("Length of keyText int after newline to null terminator: %d\n\n",keyTextLen);
	
	
	if(keyTextLen < plainTextLen){ //check if keylength is shorter than plaintext length
		fprintf(stderr, "Error: key in file: %s is too short\n", keyTextFile); //error message
		exit(1); //exit 1 error
	}
	
	//test //check bad chars in buffers
	int badCharsResult;
	badCharsResult = checkBadChars(plainText, plainTextLen);
	if(badCharsResult == -1){
		fprintf(stderr, "Bad Characters in %s\n", plainTextFile); //print error message
		exit(1); //exit 1 error
	}
	badCharsResult = checkBadChars(keyText, keyTextLen);
	if(badCharsResult == -1){
		fprintf(stderr, "Bad Characters in %s\n", keyTextFile); //print error message
		exit(1); //exit 1 error
	}
	

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	//portNumber = atoi(argv[2]); // Get the port number, convert to an integer from a string; original
	portNumber = atoi(argv[3]); //get the portnumber, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	//serverHostInfo = gethostbyname(argv[1]); // Convert the machine name into a special form of address; original
	serverHostInfo = gethostbyname("localhost");
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(2); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0){
		fprintf(stderr, "CLIENT: ERROR opening socket port: %d", portNumber);
		exit(2); //exit 2 error code
	} 
	
	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){ // Connect socket to address
		fprintf(stderr, "CLIENT: ERROR connecting port: %d", portNumber);
		exit(2);
	}


	/****************************************************************************************************
	//messaging server section
	//1) send "encoder" messsage to server. Exit with status 2 if doesn't recieve correct signal back
	//2) send plaintext to otp_enc_d
	//3) send key to otp_enc_d
	//3) recieve ciphertext and output to stdout
	//4) exit with exit 0
	****************************************************************************************************/
	
	int returnStatus = -5;
	
	/********
	 * 1) Confirmation encoder message
	********/
	//set up encoder message signaling server that it is an otp_enc client
	char confirmMessage[8] = "encoder";
	charsWritten = send(socketFD, confirmMessage, strlen(confirmMessage), 0);
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
	if (charsWritten < strlen(confirmMessage)) printf("CLIENT: WARNING: Not all data written to socket!\n");
	
	// Get return message from server
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
	charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
	if (charsRead < 0) error("CLIENT: ERROR reading from socket");
	//printf("CLIENT: I received this from the server: \"%s\"\n", buffer);
	
	returnStatus = strcmp(buffer, "terminate"); //check if client recieved the terminate message in response
	if(returnStatus == 0){ //it did so terminate
		fprintf(stderr, "otp_enc tried to connect to otp_dec_d on port %d; illegal operation terminating\n", portNumber); //print error message
		close(socketFD); // Close the socket
		
		exit(2); //exit 2 error
	}
	//didn't recieve terminate so continue on
	/*******************
	 * 2) Send plaintext to otp_enc_d
	********************/
	int convertedPlainTextSize = htonl(plainTextLen); //convert plainTextLen into sendable data
	charsWritten = send(socketFD, &convertedPlainTextSize, sizeof(convertedPlainTextSize), 0);
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
	if (charsWritten < sizeof(convertedPlainTextSize)) printf("CLIENT: WARNING: Not all data written to socket!\n");
	
	//send plainText to server
	size_t plainTextTry;
	do{
		plainTextTry = 0;
		plainTextTry = writeToFD(socketFD, plainText, strlen(plainText));
		//printf("plainTextTry = %zu\n", plainTextTry);
	} while ((plainTextTry != (size_t) plainTextLen)); //send until full length is sent
	//at this point we know the correct amount of information was sent to server so we know it has plaintext
	
	//recieve message back to clear up traffic before sending key
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
	charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
	if (charsRead < 0) error("CLIENT: ERROR reading from socket");
	//printf("CLIENT: I received this from the server: \"%s\"\n", buffer);
	
	/***************
	 * 3) Send Key to otp_enc_d
	****************/
	//send keysize
	int convertedKeyTextSize = htonl(keyTextLen); //convert plainTextLen into sendable data
	charsWritten = send(socketFD, &convertedKeyTextSize, sizeof(convertedKeyTextSize), 0);
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
	if (charsWritten < sizeof(convertedKeyTextSize)) printf("CLIENT: WARNING: Not all data written to socket!\n");
	
	//send key
	size_t keyTextTry;
	do{
		keyTextTry = 0;
		keyTextTry = writeToFD(socketFD, keyText, strlen(keyText));
		//printf("keyTextTry = %zu\n", keyTextTry);
		
	} while ((keyTextTry != (size_t) keyTextLen)); //send until full length is sent
	
	//recieve message back to clear up traffic before recieving ciphertext
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
	charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
	if (charsRead < 0) error("CLIENT: ERROR reading from socket");
	//printf("CLIENT: I received this from the server: \"%s\"\n", buffer);
	
	//send ready for cipher text
	charsWritten = send(socketFD, "READY FOR CIPHER TEXT", 22, 0);
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
	
	/******************
	 * 4) Recieve cipherText and output to stdout
	******************/
	//recieve cipherText. Create cipherTextRecv with CIPHER_TEXT_MAX_SIZE to handle maximum c string size
	char cipherTextRecv[CIPHER_TEXT_MAX_SIZE]; //allocate 70000 byte buffer for maximum cipherText size
	memset(cipherTextRecv, '\0', CIPHER_TEXT_MAX_SIZE); //null terminator out
	
	
	//set up select for this recieve
	fd_set readFDs;
	struct timeval timeToWait;
	int retval;
	
	FD_ZERO(&readFDs);					//zero readFile Descriptor
	FD_SET(socketFD, &readFDs);			//client listens on socketFD for recieving messages and sending but we only care about recieving
	
	timeToWait.tv_sec = 4; //wait for 4 seconds maximum
	timeToWait.tv_usec = 0; //zero microseconds
	
	retval = select(socketFD + 1, &readFDs, NULL, NULL, &timeToWait); //watch socketFD for reading. Don't care about writing/error. Wait 4 seconds
	
	if(retval == -1){
		perror("select()");
	}
	else if (retval) { //can be read now
		
		//printf("CLIENT: select() returned. cipherText can be read now\n");
		//printf("CLIENT: checking FD int socketFD: %d\n", socketFD);
		
		//recieve cipher text into cipherTextRecv
		size_t cipherTextTry;
		//int counter = 0;
		do{
			cipherTextTry = 0;
			cipherTextTry = readFromFD(socketFD, cipherTextRecv, strlen(plainText));
			//fprintf(stderr, "cipherTextTry = %zu\n", cipherTextTry);
			
			//counter++;
			//if(counter == 2){ break;}
			
		} while(cipherTextTry != (size_t) plainTextLen); //read until full length is read of expected text
		//fprintf(stderr, "CLIENT: Got a message. Not going to print now because I am just testing\n");
		//printf("CLIENT: cipherTextTry: %zu, expected: %d\n", cipherTextTry, plainTextLen);
		
		
	}
	else{
		printf("No data within 4 seconds\n");
	}
	
	//fprintf(stderr, "CLIENT: size of cipherTextRecv to stdout: %zu\n", strlen(cipherTextRecv));
	//output cipherText to stdout
	
	/*************************
	 * FINAL PRINT TO STD OUT ALWAYS KEEP THIS ACTIVE!!!
	*************************/
	fprintf(stdout, "%s\n", cipherTextRecv); //output cipherTextRecv with a \n character
	
	/*************************
	 * FINAL PRINT TO STD OUT ALWAYS KEEP THIS ACTIVE!!!
	*************************/
	
	
	//printf("CLIENT: I received this from the server: \"%s\"\n", cipherTextRecv);
	//printf("Server: Length of plaintext Message: %zu\n", strlen(cipherTextRecv));
	//printf("Server: Bytes Read of plaintext Message: %d\n", charsRead); //charsRead = bytes returned from recv
	//printf("Expected Length: %d Expected bytes: %zu\n", ntohl(plainTextRecvSize), plainTextExpectedSize);
	
	
	
	close(socketFD); // Close the socket
	
	free(plainText);	//free plaintext
	plainText = NULL;	//null plainText
	free(keyText);		//free keyText
	keyText = NULL;		//null keyText
	
	return 0;
}

//testing buffers
void printBuffer(char Buffer[], int size){
	int i;
	for(i = 0; i < size; i++){
		printf("%c  =>  %d\n",Buffer[i], Buffer[i]);
	}
	
}


//read from passed fileName into fileText by pointing to buffer
ssize_t readFile(char** fileText, char* fileName){
	FILE * fp;				//file stream
	char* buffer = NULL;	//null buffer for now
	size_t len = 0;
    ssize_t read;
    
    fp = fopen(fileName, "r"); //open file specified by fileName
    if (fp == NULL)
        exit(EXIT_FAILURE);	//can't open exit failure

    while ((read = getline(&buffer, &len, fp)) != -1) {		//read into buffer
        //printf("Retrieved line of length %zu :\n", read);
       // printf("%s", buffer);
    }

    fclose(fp);
    
    *fileText = buffer;
    
    return len;
}

//checks Buffer string for bad characters. Returns -1 for a bad character in the string and 0 for no bad characters
int checkBadChars(char Buffer[], int size){
	int result = 0; //assign as all good characters
	int i; //iterator
	
	for(i = 0; i < size; i++){
		if(Buffer[i] < 'A' || Buffer[i] > 'Z'){ //check if below ascii values 'A' or above 'Z'
			if(Buffer[i] != ' '){ //make sure it isn't ascii 32 == ' '
				result = -1; //if it isn't its a bad character return bad result
			}
		}
	}
	
	return result;
}


//Reads from file descriptor passed in from function call. Uses bufferToWrite and numberToWrite to send to client/server
//will run until totalWritten bytes == numberToWrite bytes that is passed in. Should be run in a while loop above to make sure it returns the right amount of bytes
//uses bufPointer to point to bufferToWrite for ease of reading for later use
//counts number of bytes written and returns to function call. Should be run in a while loop if actual sent != expected sent
size_t writeToFD(int FD, const char* bufferToWrite, size_t numberToWrite){
	size_t numberWritten = 0; //number of bytes written so far
	size_t totalWritten = 0; //total number of bytes written
	const char* bufPointer; //pointer to bufferToWrite
	
	bufPointer = bufferToWrite; //point to buffer to write
	
	/* Testing printfs
	printf("FD int = %d\n", FD);
	printf("I am in the writeToFD() function \n");
	printf("writeToFD() trying to write: %s\n", bufferToWrite);
	printf("bufPointer: %s\n", bufPointer);
	printf("passed numberToWrite = %zu\n", numberToWrite);
	printf("numberToWrite - totalWritten = %zu\n", numberToWrite-totalWritten);
	*/
	while(totalWritten < numberToWrite){ //write until totalWriten is numberToWrite
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
	printf("CLIENT: I am in the readFromFD() function \n");
	printf("passed numberToRead = %zu\n", numberToRead);
	printf("numberToRead - totalRead = %zu\n", numberToRead-totalRead);
	*/
	
	while(totalRead < numberToRead){ //try writing up to the point of numberToWrite
		numberRead = recv(FD, bufPointer, numberToRead - totalRead, 0); //read bytes left to read into bufPointer -> bufferReadIn
		
		//printf("CLIENT: numberRead from within readFromFD while loop: %zu\n", numberRead);
		//fprintf(stderr, "CLIENT: numberRead from within readFromFD while loop: %zu\n", numberRead);
		
		
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