/*Shane Klumpp Project 4 Keygen.c file. Creates the key for decrepting/encrypting plaintext into cryptotext
Your program will encrypt and decrypt plaintext into ciphertext, using a key, in exactly the same fashion as above
except it will be using modulo 27 operations: your 27 characters are the 26 capital letters,
and the space character ( ). All 27 characters will be encrypted and decrypted as above
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

//prototype
void printBuffer(char Buffer[], int size);

int main(int argc, char*argv[]){
    
    int i; //iterator
    int keyLength; //holds length of key that needs to be created. Final keyLength will be keyLength + 1 for the \n character
    
    srand(time(NULL)); //set seed
    
    //catch wrong number of command line arguments
    if(argc <= 1){
        perror("You didn't feed me arguments so now I must exit disgracefully\n"); //print to stderr
        exit(1); //error not enough arguments
    }

    //printf("Converting argv[1] string: %s to integer\n",argv[1]);
    //fflush(stdout);
    
    keyLength = atoi(argv[1]); //ascii to integer function converts string in argv[1] to integer in variable keyLength
    
   // printf("argv[1] is now an integer %d\n",keyLength);
    //fflush(stdout);
    
    char* keyString = malloc((keyLength+1)*sizeof(char)); //allocate space for keyString with keyLength + 1 for \n character
    int keyStringSize = keyLength + 1; //keyLength + 1 for \n character
    
    //printBuffer(keyString, keyStringSize);
    
    char currChar; //current char
    
    for(i = 0; i < keyLength; i++){ //iterate through keylength
        currChar = 'A' + (rand() % 27); //random character between 'A' and 'Z' including '[' which will be turned into a ' ' space
        //printf("Current Char: %c\n", currChar);
        //fflush(stdout);
        
        if(currChar == '['){
            keyString[i] = ' '; //easier ascii manipulation convert ascii 92 ('[') to space to correct
        }
        else{
            keyString[i] = currChar;
        }
        //printf("Current keyString: %s\n", keyString);
        //fflush(stdout);
    }
    keyString[keyLength] = '\n'; //add newline
    
    //printBuffer(keyString, keyStringSize);
    
    fprintf(stdout, "%s", keyString);
    
    
    free(keyString); //free allocated memory
    keyString = NULL;
    
    return 0;
}


void printBuffer(char Buffer[], int size){ //testing
	int i;
	for(i = 0; i < size; i++){
		printf("%c  =>  %d\n",Buffer[i], Buffer[i]);
	}
	
}