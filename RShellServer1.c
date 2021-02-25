/*
 *   RShellServer1.c	example program for CS 468
 */


// OpenSSL Imports
#include <openssl/sha.h>
#include <time.h>
#include <stdbool.h>

// Other Imports
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <openssl/aes.h>

// Definitions for message type
#define RSHELL_REQ 0x11
#define AUTH_CHLG 0x12
#define AUTH_RESP 0x13
#define AUTH_SUCCESS 0x14
#define AUTH_FAIL 0x15
#define RSHELL_RESULT 0x16

// Size in bytes of Message type
#define TYPESIZE 1

 // Size in bytes of Message payload length
#define LENSIZE 2

// Password size (in Hex)--> 20 bytes, 2 chars rep 1 byte, so 40 chars
#define PASSWDSIZE 40

// Max ID size: 16 - 1 = 15 bytes for id, 1 for null term
#define IDSIZE 16

// Max length of payload (2^16) = 65536
#define MAXPLSIZE 65536

// Max potential message size (2^1) + (2^2) + (2^16)
#define MAXMSGSIZE 65542

// Command size- sub
#define MAXBUFSIZE ((MAXPLSIZE - IDSIZE) - 1)

// provided code definitions
#define LINELEN     (MAXBUFSIZE - 20)
#define BUFSZ       (MAXBUFSIZE - 20)
#define resultSz    (MAXPLSIZE - 1)


// Typedef for the message format
typedef struct Message{
    // Message type
    char msgtype;
    // payload length in bytes
    short paylen;
    // id for the first 16 bytes of the payload
    char id[IDSIZE];
    // the payload
    char *payload;
}Message;

// Method to determine the message type.
int decode_type(Message *msg){
    switch(msg -> msgtype){
        case RSHELL_REQ :
            printf("Received RSHELL_REQ message.\n");
            return 1;
            break;
        case AUTH_CHLG :
            printf("Received AUTH_REQ message.\n");
            return 2;
            break;
        case AUTH_RESP :
            printf("Received AUTH_RESP message.\n");
            return 3;
            break;
        case AUTH_SUCCESS :
            printf("Received AUTH_SUCCESS message.\n");
            return 4;
            break;
        case AUTH_FAIL :
            printf("Received AUTH_FAIL message.\n");
            return 5;
            break;
        case RSHELL_RESULT :
            printf("Received RSHELL_RESULT message.\n");
            return 6;
            break;
        default :
            printf("ERROR: Received Invalid message.\n");
            return -1;
            break;
    }
}

// Debug method to print a Message
void print_message(Message *msg){
    printf("MESSAGE--> TYPE:0x%d   PAYLEN:%d  ID:%s   PAYLOAD:%s\n\n", msg->msgtype, msg->paylen, msg->id, msg->payload);
}

int serversock(int UDPorTCP, int portN, int qlen){
    struct sockaddr_in svr_addr;    /* my server endpoint address       */
    int    sock;            /* socket descriptor to be allocated    */

    if (portN<0 || portN>65535 || qlen<0)   /* sanity test of parameters */
        return -2;

    bzero((char *)&svr_addr, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_addr.s_addr = INADDR_ANY;

    /* Set destination port number */
    svr_addr.sin_port = htons(portN);

    /* Allocate a socket */
    sock = socket(PF_INET, UDPorTCP, 0);
    if (sock < 0)
        return -3;

    /* Bind the socket */
    if (bind(sock, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) < 0)
        return -4;

    if (UDPorTCP == SOCK_STREAM && listen(sock, qlen) < 0)
        return -5;

    return sock;
}

inline int serverTCPsock(int portN, int qlen){
  return serversock(SOCK_STREAM, portN, qlen);
}

inline int serverUDPsock(int portN){
  return serversock(SOCK_DGRAM, portN, 0);
}

void usage(char *self){
    // Useage message when bad # of arguments
    fprintf(stderr, "Usage: %s <port to run server on> <password file> \n", self);
    exit(1);
}

void errmesg(char *msg){
    fprintf(stderr, "**** %s\n", msg);
    exit(1);
}

/*------------------------------------------------------------------------
 * reaper - clean up zombie children
 *------------------------------------------------------------------------
 */
void reaper(int signum){
    /*
     union wait  status;
    */
    int status;
    while (wait3(&status, WNOHANG, (struct rusage *)0) >= 0)
    /* empty */;
}

/*------------------------------------------------------------------------
 *  This is a very simplified remote shell, there are some shell command it
    can not handle properly:

    cd
 *------------------------------------------------------------------------*/
int RemoteShellD(int sock){
    char cmd[BUFSZ+20];
    char result[resultSz];
    int cc, len;
    int rc=0;
    FILE *fp;

    printf("***** RemoteShellD(sock=%d) called\n", sock);

    while ((cc = read(sock, cmd, BUFSZ)) > 0)   /* received something */
    {
        if (cmd[cc-1]=='\n')
            cmd[cc-1]=0;
        else cmd[cc] = 0;

        printf("***** RemoteShellD(%d): received %d bytes: `%s`\n", sock, cc, cmd);

        strcat(cmd, " 2>&1");

        printf("***** cmd: `%s`\n", cmd);

        if ((fp=popen(cmd, "r"))==NULL) /* stream open failed */
            return -1;

        /* stream open successful */

        while ((fgets(result, resultSz, fp)) != NULL)   /* got execution result */
        {
            len = strlen(result);
            printf("***** sending %d bytes result to client: \n`%s` \n", len, result);

            if (write(sock, result, len) < 0)
            { rc=-1;
              break;
            }
        }
        fclose(fp);
    }

    if (cc < 0)
        return -1;

    return rc;
}

// Modified Remote Shell method, builds message for remote shell command
Message * MsgRemoteShell(char *command, char *id){
    char result[resultSz];
    FILE *fp;

    memset(result, 0, resultSz);

    Message *msg = (Message*)(malloc(sizeof(Message)));

    if ((fp = popen(command, "r")) == NULL){
        /* stream open failed */
        return NULL;
    }

    printf("");

    // Combine stderr and stdout in command
    strcat(command, " 2>&1");

    // read result of execution
    fread(result, resultSz, 1, fp); 

    // close file
    pclose(fp);

    // null term result
    result[strlen(result) - 1] = '\0';

    // Set message type
    msg->msgtype = RSHELL_RESULT;
    // Set payload length 16 for id
    msg->paylen = IDSIZE + strlen(result);
    // Set 16 byte id, 15 bytes for user ID max
    memcpy(msg->id,id,(IDSIZE - 1));
    // Ensure the user ID is null-terminated
    msg->id[strlen(id)] = '\0';
    msg->payload = result;

    printf("The result from command '%s' was:\n%s\n\n", command, result);

    return msg;
}


// Writes messages to socket: Returns 0 if successful, 1 if there was an error
int write_message(int sock, Message *msg){
    // Size will be the message type + paylen + ID + payload
    int msgsize = sizeof(char) + sizeof(short) + (sizeof(char) * msg->paylen);
    // n will store return value of write()
    int n;

    //printf("The size of the message you are sending is: %d\n", msgsize);

    // Write the message type 
    if ( (n = write(sock, &msg->msgtype, TYPESIZE)) != TYPESIZE ){
        printf("ERROR: Has %d byte send when trying to send %d bytes for Message Type: `%s`\n", n, TYPESIZE, &msg);
        close(sock);
        return -1;
    }

    // Write the message length
    if ( (n = write(sock, &msg->paylen, LENSIZE)) != LENSIZE ){
        printf("ERROR: Has %d byte send when trying to send %d bytes for Message Length: `%s`\n", n, LENSIZE, &msg);
        close(sock);
        return -1;
    }

    // Write the user ID
    if(msg->paylen >= IDSIZE){
        if ( (n = write(sock, &msg->id, IDSIZE)) != IDSIZE ){
            printf("ERROR: Has %d byte send when trying to send %d bytes for Message UserID: `%s`\n", n, IDSIZE, &msg);
            close(sock);
            return -1;
        }
    }

    // Write the payload, check IDSIZE + 1 for null term
    if(msg->paylen > IDSIZE + 1){
        if ( (n = write(sock, msg->payload, (msg->paylen - IDSIZE) )) != (msg->paylen - IDSIZE) ){
            printf("ERROR: Has %d byte send when trying to send %d bytes for Message UserID: `%s`\n", n, (msg->paylen - IDSIZE), &msg);
            close(sock);
            return -1;
        }
    }

    return 0;
}



// Reads message from socket, returns NULL if there is an error during read
Message * read_message(int sock){
    // Create pointer to hold in the message read-in
    Message *msg = (Message*)(malloc(sizeof(Message)));

    // Read the message type
    if (read(sock, &msg->msgtype, TYPESIZE) != TYPESIZE){
        // Return NULL if there is an error
        // printf("ERROR: Could not read message type.\n");
        // Will reach here when client disconects.
        printf("Client has disconnected from the Server.\n"); 

        // Free memory
        free(msg);
        // Return NULL b/c of error
        return NULL;
    }

    // Read the message length
    if (read(sock, &msg->paylen, LENSIZE) != LENSIZE){
        // Return NULL if there is an error
        printf("ERROR: Could not read message length.\n");
        // Free memory
        free(msg);
        // Return NULL b/c of error
        return NULL;
    }

    // Check if 16 bytes of ID exists
    if(msg->paylen >= IDSIZE){
        // Write the user ID
        if ( (read(sock, &msg->id, IDSIZE)) != IDSIZE ){
            printf("ERROR: Could not read message ID.\n");
            // Free memory
            free(msg);
            // Return NULL b/c of error
            return NULL;
        }
    }

    // Check if more 16 bytes of length exist, b/c first 16 is ID, the rest would be payload...
    if(msg->paylen > IDSIZE){
        // Need to malloc new memory for the incoming payload
        // The size is the payload size described in the message - the ID bytes
        msg->payload = (char*)malloc( (msg->paylen - IDSIZE) * sizeof(char));
        // Write the payload
        if ( (read(sock, msg->payload, (msg->paylen - IDSIZE) )) != (msg->paylen - IDSIZE) ){
            printf("ERROR: Could not read message payload.\n");
            // Free memory
            free(msg);
            // Return NULL b/c of error
            return NULL;
        }
    }

    // Return pointer to read-in message
    return msg;
}



/*-------------------------------------------------------------------------------
 * Method to Authenticate sent client information with user/pass in password file
 *------------------------------------------------------------------------------*/
// Simple function for authentication
// Takes Client username, SHA1 hashed client password and compares to
// Server username and server SHA1 hashed password (read in from password file)
bool authenticate (char cluser[], unsigned char clpass[], char *pwdfname){

    // Username stored on the server read from the passwdfile.txt
    char *seruser;
    // SHA1 hashed password stored on the server read from the passwdfile.txt
    unsigned char *serpass;

    // user string with client user length
    char svruser[sizeof(cluser)];
    // hashed password string with client pass length
    char svrpass[sizeof(clpass)];

    // Open and read the password file

    // Contains the format: <Username>; <hex representation of SHA1(PW)>
    // Example if the User was "Alice" and the password was "SecretPW":
    //      Alice; 0c8f72ea98dc74c71f9ff5bb72941036ae5120d9

    // Will parse the first line of the password file for the username and SHA1 password hash
    // Will first read line for username until finds the ";" symbol
    // Then after the ";" symbol will ignore whitespace and save the SHA1 hash in "hashedpass"

    // The password file
    FILE *passwdfile;

    // initialize line to null
    char *line = NULL;

    // Input / Output primatives
    // Length of line read
    size_t linelen = 0;
    // to read line from file
    ssize_t read;

    // Open the password file
    passwdfile = fopen(pwdfname, "r");

    // Check if the password file could be opened
    if (passwdfile == 0){
        // Not found or could not open
        printf("The specified password file was not found or could not be opened.\n");
        // Exit the program
        exit(1);
    }else{
        // The file could be opened, so read its contents
        // The file should only have 1 line in it (as defined in the spec)
        read = getline(&line, &linelen, passwdfile);

        // Close the password file when done
        fclose(passwdfile);

        // Parse the line for the username and SHA1 hash of the password
        char* linebuf;

        // Split on ";" symbol, get username
        linebuf = strtok(line, ";");
        // Copy into username
        memcpy(&seruser, &linebuf, sizeof(seruser));

        // Split on ";" symbol, get password
        linebuf = strtok(NULL, ";");
        // Trim lead whitespace before the SHA1 password hash
        while(isspace(*linebuf)){
            linebuf++;
        }
        // Get rid of the ending newline character from SHA1 hash
        linebuf = strtok(linebuf, "\n");

        // Copy into hashedpass
        memcpy(&serpass, &linebuf, sizeof(serpass));

        // Now the username and SHA1 hashed pass have been read from the password file
        // and stored into memory

        // Test print statements to see if username and password were read correctly from file
        printf("Password file Username: \"%s\"\n", seruser);
        printf("Password file Password: \"%s\"\n", serpass);

        // Test Client username and password
        printf("Client Username: \"%s\"\n", cluser);
        printf("Client Password: \"%s\"\n", clpass);

        // Check if usernames match
        if(strcmp(cluser, seruser) == 0){

            // The IDs are a match, so check if the hashed passwords match
            if(strcmp(clpass, serpass) == 0){
                // The passwords match! So this is an AUTH_SUCESS
                printf("Authentication success!\n\n");
                // Free the line
                free(line);
                return true;
            }else{
                // Hashed password did not match
                printf("Password did not match.\n\n");
            }
        }else{
            // Username did not match
            printf("Invalid ID: %s\n\n", cluser);
        }
    }
    // Free the line
    free(line);
    // Username or password did not match, so this is an AUTH_FAIL
    return false;
}



/*------------------------------------------------------------------------
 * main - Concurrent TCP server
 *------------------------------------------------------------------------*/
int main(int argc, char *argv[]){
	//auth variables
	char *passfname; // server pasword file name
	char *rshellcmd; //command client wants to run
	Message *msg; // message pointer
	char id[IDSIZE]; // user id

	bool auth = false; //true is authenticated else false (> 60 secs)
	struct timeval authtime; //time of authentication
	struct timeval reqtime; //time of request for command

	//mock credentials
	//char userid[] = "Alice";
	//unsigned char mockpw[] = "0c8f72ea98dc74c71f9ff5bb72941036ae5120d9";	
	
	unsigned char *password; //var to hold hashed password
	
	//server variables
	int msock; //master server socket
	int ssock; //slave server socket
	int portN; //port number to listen to
	struct sockaddr_in fromAddr; //the from address of a client
	unsigned int fromAddrLen; //from address length		    
	int prefixL, r;
	
	//nonce
	srand(2222);
	int nonce1;
	int nonce2 = (unsigned long)rand();
	char *nonce1buf;
	char nonce2buf[12];
	nonce2buf[0] = '\0';
	snprintf(nonce2buf, 12, "%d", nonce2);
	//nonce2buf[strlen(nonce2buf)] = '\0';
	
	//sanity check for 3 args
	if (argc == 3){
		portN = atoi(argv[1]); //set port number
		passfname = argv[2]; //set password filename
	}
	else {
		usage(argv[0]); //show proper format
	}

	//take out the password and the user name from file provided
	FILE *passwdfile; //the password file
	char *line = NULL; //init line to null
	size_t linelen = 0; //length of line
	size_t read; //to read from file
	passwdfile = fopen(passfname, "r"); //open the password file
	if (passwdfile == 0){
		printf("Password file is empty.\n");
		exit(1);
	}
	else {
		read = getline(&line, &linelen, passwdfile); //read it
		fclose(passwdfile); //close file after reading one line
		char *linebuf; //parse the file for username and sha1 pw
		linebuf = strtok(line, ";"); //split on ; symbol to get username
		memcpy(&id, &linebuf, sizeof(id)); //copy into username
		linebuf = strtok(NULL, ";"); //split of ; symbol to get password
		while (isspace(*linebuf)){
			linebuf++; //trim lead whitespace
		}
		linebuf = strtok(linebuf, "\n"); //get rid of \n
		memcpy(&password, &linebuf, sizeof(password)); //copy into hashed password
	}
			
	msock = serverTCPsock(portN, 5);
	
	(void) signal(SIGCHLD, reaper);
	
	while (1){
		fromAddrLen = sizeof(fromAddr);
		ssock = accept(msock, (struct sockaddr *)&fromAddr, &fromAddrLen);
		if (ssock < 0){
			if (errno == EINTR)
				continue;
			errmesg("accept error\n");
		}
		switch (fork()){
			case 0: //child
				close(msock);
				printf("Client has connected to the Server.\n");
				//listen for client message
				while(msg = read_message(ssock)){
					if (msg != NULL){
						printf("Received Message from Client:\n");
						print_message(msg);
						gettimeofday(&reqtime,NULL);
						//set auth to false if have been authenticated for more than 60 seconds
						if ((reqtime.tv_sec - authtime.tv_sec) > 60){
							printf("More than 60 seconds have passed, setting user authentication to false.\n\n");
							auth = false;
						}
						if (!auth){
							//user hasnt been authenticated yet
							switch (msg -> msgtype){
								case RSHELL_REQ:
								{
									nonce1buf = (char*)malloc((msg->paylen - IDSIZE) * sizeof(char)); //save the command
									memcpy(nonce1buf, msg->payload, strlen(msg->payload));
									nonce1buf[(msg->paylen - IDSIZE) ] = '\0'; //ensure the null terminated
									sscanf(nonce1buf, "%d", &nonce1); //save nonce1
									memcpy(id,msg->id,IDSIZE); //copy id from message
									id[strlen(id)] = '\0'; //ensure its null terminated
									free(msg); //free message
									
									//create an AUTH_CHLG
									msg = malloc(sizeof(Message));
									msg->msgtype = 0x12; //AUTH_CHLG; //set message type
									msg->paylen = IDSIZE; //set payload length 16 for id
									memcpy(msg->id,id,(IDSIZE - 1)); //memcpy(msg->id,id,(IDSIZE - 1));
									msg->id[strlen(id)] = '\0'; //ensure null termination
									msg->payload = nonce2buf; //payload is nonce2
									
									//write the AUTH_CHLG message
									printf("Sending the following Message from Server to Client:\n");
									print_message(msg);
									write_message(ssock, msg);
									break;
								}
								case AUTH_RESP:
									break;//write_message(ssock, msg); printf("boo yah\n"); break;
								/*{
									char *clenc;
									clenc = (char*)malloc((msg->paylen - IDSIZE) * sizeof(char)); //save the command 
									memcpy(clenc, msg->payload, strlen(msg->payload));
									clenc[(msg->paylen - IDSIZE) ] = '\0'; //ensure the null terminated
									char clnonce2[strlen(clenc)];
                                                                        int a = 0; int b = 0; int c = 0; //ctrs
                                                                        for (a = 0; a < strlen(clenc); a++){
                                                                                if (isalpha(clenc[a])){
                                                                                        rshellcmd[b] = clenc[a];
                                                                                        b++;
                                                                                }
                                                                                else {
                                                                                        clnonce2[c] = clenc[a];
                                                                                        c++;
                                                                                }
                                                                        }
                                                                        int clnonce = 0;
                                                                        sscanf(clnonce2, "%d", &clnonce);
                                                                        clnonce--; //for experiments to fail comment this line out
									if (nonce2 == clnonce){
                                                                                auth = true; // set auth to true
                                                                                gettimeofday(&authtime,NULL); //set time of auth
                                                                                free(msg); //free current message

                                                                                //create AUTH_SUCCESS
                                                                                msg = malloc(sizeof(Message));
                                                                                msg->msgtype = 0x14;//AUTH_SUCCESS; //set message type
printf("error!!");                                                                                msg->paylen = IDSIZE; //set payload len at 16
                                                                                memcpy(msg->id,id,(IDSIZE - 1)); //set 16 byte id, 15 bytes for user ID max
                                                                                msg->id[strlen(id)] = '\0'; //ensure null termination
                                                                                //payload is nonce 1+1 encrytped
                                                                                int nn1 = nonce1+1;
                                                                                char nn1buf[strlen(nonce1buf)];
                                                                                snprintf(nn1buf, 12, "%d", nn1);
                                                                                msg->payload = nn1buf; //set payload to encrypted nonce

                                                                                //write the AUTH SUCCESS
                                                                                printf("Sending the following Message from Server to Client:\n");
                                                                                print_message(msg);
                                                                                write_message(ssock, msg);

                                                                                //now run the command
                                                                                free(msg);
                                                                                printf("The RShell command to be run on the Server is: %s\n\n", rshellcmd);
                                                                                msg = MsgRemoteShell(rshellcmd, id); //create a an RSHELL_RESULT message
                                                                                printf("Sending the following Message from Server to Client:\n");
                                                                                print_message(msg);
                                                                                write_message(ssock, msg);
                                                                                free(msg); //free msg
                                                                                free(rshellcmd); //free rshellcommand
                                                                                break;
                                                                        }	
									else {
                                                                                //auth fail
                                                                                //free(password);
                                                                                auth = false;
                                                                                free(msg); //free current message

                                                                                //create a an AUTH_FAIL message
                                                                                msg = malloc(sizeof(Message));
printf("error!!");                                                                                msg->msgtype = 0x15;//AUTH_FAIL; //set message type
                                                                                msg->paylen = IDSIZE; //set payload length 16 for id
                                                                                memcpy(msg->id,id,(IDSIZE - 1)); //set 16 byte id, 15 bytes for user ID max
                                                                                msg->id[strlen(id)] = '\0'; //ensure null termination
                                                                                msg->payload = nonce1buf; //send unaltered nonce 1 as payload

                                                                                //write the AUTH_FAIL
                                                                                printf("Sending the following Message from Server to Client:\n");
                                                                                print_message(msg);
                                                                                write_message(ssock, msg);
                                                                        }
                                                                        break;
									//nonce1buf = (char*)malloc((msg->paylen - IDSIZE) * sizeof(char)); //save the command
                                                                        //memcpy(nonce1buf, msg->payload, strlen(msg->payload));
                                                                        //nonce1buf[(msg->paylen - IDSIZE) ] = '\0'; //ensure the null terminated
                                                                        //sscanf(nonce1buf, "%d", &nonce1); //save nonce1
									//
								}*/
								/*
								{
									printf("");
									//set up key SHA256(SHA1(PW)|Nonce1|Nonce2)
									int tmpkey_size = (strlen(password) + strlen(nonce1buf) + strlen(nonce2buf));
									unsigned char tmpkey[tmpkey_size * 2]; //will contain the key for encrytption
									strcat(tmpkey, password); //concatenate the strings
									strcat(tmpkey, nonce1buf);
									strcat(tmpkey, nonce2buf);
									//sha256 the tmpkey to get the encrytption key
									unsigned char temphash[SHA256_DIGEST_LENGTH];
									unsigned char key[SHA256_DIGEST_LENGTH * 2];
									SHA256_CTX sha256;
									SHA256_Init(&sha256);
									SHA256_Update(&sha256, tmpkey, strlen(tmpkey));
									SHA256_Final(temphash, &sha256);
									int j = 0;
									for(j = 0; j < SHA256_DIGEST_LENGTH; j++){
										sprintf( ((unsigned char*) &(key[j * 2])), "%02x", temphash[j]);
									}
									//set up the iv vector SHA256(Nonce1|Nonce2)
									int ivsize = (strlen(nonce1buf) + strlen(nonce2buf));
									unsigned char tmpiv[ivsize * 2]; //will contain the temp iv
									strcat(tmpiv, nonce1buf); //concatenate the strings
									strcat(tmpiv, nonce2buf);
									//sha256 the tmp iv to get the encryption iv
									unsigned char tempiv[SHA256_DIGEST_LENGTH];
									unsigned char sha_iv[SHA256_DIGEST_LENGTH * 2];
									//SHA256_CTX sha256;
									//SHA256_Init(&sha256);
									SHA256_Update(&sha256, tmpkey, strlen(tmpkey));
									SHA256_Final(temphash, &sha256);
									for(j = 0; j < SHA256_DIGEST_LENGTH; j++){
										sprintf( ((unsigned char*) &(sha_iv[j * 2])), "%02x", tempiv[j]);
									}
									unsigned char iv[16];
									for (j = 0; j < 16; j++){
										iv[j] = sha_iv[j];
									}
									//decrypt the file
									unsigned char *in;
									in = (char *) malloc((msg->paylen - IDSIZE) * sizeof(char) + 1);
									strcpy(in, msg->payload);
									size_t dec_len = ((strlen(in) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
									unsigned char dec_out[dec_len];
									memset(dec_out, 0, sizeof(dec_out)); //memory allocation for enc buffer
									//decryption process
									AES_KEY aes_key;
									AES_set_decrypt_key(key, strlen(key), &aes_key);
									AES_cbc_encrypt(in, dec_out, strlen(in), &aes_key, iv, AES_DECRYPT);
									//authenticate using nonce2+1
									//extract the nonce and the r shell command
									char clnonce2[strlen(dec_out)];
									int a = 0; int b = 0; int c = 0; //ctrs
									for (a = 0; a < strlen(dec_out); a++){
										if (isalpha(dec_out[a])){
											rshellcmd[b] = dec_out[a];
											b++;
										}
										else {
											clnonce2[c] = dec_out[a];
											c++;
										}
									}
									int clnonce = 0;
									sscanf(clnonce2, "%d", &clnonce);
									clnonce--;
									if (nonce2 == clnonce){
										free(password);
										auth = true; // set auth to true
										gettimeofday(&authtime,NULL); //set time of auth
										free(msg); //free current message
										
										//create AUTH_SUCCESS
										msg = malloc(sizeof(Message));
										msg->msgtype = AUTH_SUCCESS; //set message type
										msg->paylen = IDSIZE; //set payload len at 16
										memcpy(msg->id,id,(IDSIZE - 1)); //set 16 byte id, 15 bytes for user ID max
										msg->id[strlen(id)] = '\0'; //ensure null termination
										//payload is nonce 1+1 encrytped
										int nn1 = nonce1+1;
										char nn1buf[strlen(nonce1buf)];
										snprintf(nn1buf, 12, "%d", nn1);
										unsigned char *encn1;
										memset(encn1, 0, sizeof(encn1)); //memory allocation for enc buffer
										AES_KEY aes_key;
										AES_set_encrypt_key(key, strlen(key), &aes_key);
										AES_cbc_encrypt(nn1buf, encn1, strlen(nn1buf), &aes_key, iv, AES_DECRYPT);
										msg->payload = encn1; //set payload to encrypted nonce
										
										//write the AUTH SUCCESS
										printf("Sending the following Message from Server to Client:\n");
										print_message(msg);
										write_message(ssock, msg);

										//now run the command
										free(msg);
										printf("The RShell command to be run on the Server is: %s\n\n", rshellcmd);
										msg = MsgRemoteShell(rshellcmd, id); //create a an RSHELL_RESULT message
										printf("Sending the following Message from Server to Client:\n");
										print_message(msg);
										write_message(ssock, msg);
										free(msg); //free msg
										free(rshellcmd); //free rshellcommand
										break;
									}
									else {
										//auth fail
										free(password);		
										auth = false;
										free(msg); //free current message
										
										//create a an AUTH_FAIL message
										msg = malloc(sizeof(Message));
										msg->msgtype = AUTH_FAIL; //set message type
										msg->paylen = IDSIZE; //set payload length 16 for id
										memcpy(msg->id,id,(IDSIZE - 1)); //set 16 byte id, 15 bytes for user ID max
										msg->id[strlen(id)] = '\0'; //ensure null termination
										msg->payload = nonce1buf; //send unaltered nonce 1 as payload
										
										//write the AUTH_FAIL
										printf("Sending the following Message from Server to Client:\n");
										print_message(msg);
										write_message(ssock, msg);
									}
									break;
								}
								*/
								default:
									printf("ERROR: Received Invalid message.\n");
									break;
							}
						}
						else {
							printf("The user %s has already been authenticated. Will run command.\n\n", id);
                            				switch(msg -> msgtype){
                               			 		case RSHELL_REQ:
								break;/*{
									char *clenc;
                                                                        clenc = (char*)malloc((msg->paylen - IDSIZE) * sizeof(char)); //save the command 
                                                                        memcpy(clenc, msg->payload, strlen(msg->payload));
                                                                        clenc[(msg->paylen - IDSIZE) ] = '\0'; //ensure the null terminated
                                                                        int a = 0; int b = 0; //ctrs
                                                                        for (a = 0; a < strlen(clenc); a++){
                                                                                if (isalpha(clenc[a])){
                                                                                        rshellcmd[b] = clenc[a];
                                                                                        b++;
                                                                                }
                                                                        }
									rshellcmd[(msg->paylen - IDSIZE) ] = '\0'; //ensure null terminated
                                                                        memcpy(id,msg->id,IDSIZE); //copy the from the message into the server id field
                                                                        id[strlen(id)] = '\0'; //ensure null termination
                                                                        //now run the command
                                                                        free(msg);
                                                                        printf("The RShell command to be run on the Server is: %s\n\n", rshellcmd);
                                                                        msg = MsgRemoteShell(rshellcmd, id); //create a an RSHELL_RESULT message
                                                                        printf("Sending the following Message from Server to Client:\n");
                                                                        print_message(msg);
                                                                        write_message(ssock, msg);
                                                                        free(msg); //free msg
                                                                        free(rshellcmd); //free rshellcommand
                                                                        break;	
								}*/
								/*
								{
									//user has already been authenticated
									//set up key SHA256(SHA1(PW)|Nonce1|Nonce2)
                                                        		int tmpkey_size = (strlen(password) + strlen(nonce1buf) + strlen(nonce2buf));
                		                                        unsigned char tmpkey[tmpkey_size * 2]; //will contain the key for encrytption
                                		                        strcat(tmpkey, password); //concatenate the strings
                                                        		strcat(tmpkey, nonce1buf);
                                                        		strcat(tmpkey, nonce2buf);
                                                        		//sha256 the tmpkey to get the encrytption key
                                                        		unsigned char temphash[SHA256_DIGEST_LENGTH];
                                                        		unsigned char key[SHA256_DIGEST_LENGTH * 2];
                                                        		SHA256_CTX sha256;
                                                        		SHA256_Init(&sha256);    
                                                        		SHA256_Update(&sha256, tmpkey, strlen(tmpkey));
                                                        		SHA256_Final(temphash, &sha256);
                                                       			int j = 0;
                                                        		for(j = 0; j < SHA256_DIGEST_LENGTH; j++){
                                                         		    	sprintf( ((unsigned char*) &(key[j * 2])), "%02x", temphash[j]);
                                                       			 }
                                                        		//set up the iv vector SHA256(Nonce1|Nonce2)
                       	                               	 		int ivsize = (strlen(nonce1buf) + strlen(nonce2buf));
                                                        		unsigned char tmpiv[ivsize * 2]; //will contain the temp iv
                                                        		strcat(tmpiv, nonce1buf); //concatenate the strings
                                                        		strcat(tmpiv, nonce2buf);
                                                        		//sha256 the tmp iv to get the encryption iv
                                                        		unsigned char tempiv[SHA256_DIGEST_LENGTH];
                                                        		unsigned char sha_iv[SHA256_DIGEST_LENGTH * 2];
                                                        		//SHA256_CTX sha256;
                                                        		//SHA256_Init(&sha256);
                                                        		SHA256_Update(&sha256, tmpiv, strlen(tmpkey));
                                                        		SHA256_Final(temphash, &sha256);
                                                        		for(j = 0; j < SHA256_DIGEST_LENGTH; j++){
                                                           			sprintf( ((unsigned char*) &(sha_iv[j * 2])), "%02x", tempiv[j]);
                                                        		}
                                                        		unsigned char iv[16];
                       	                                		for (j = 0; j < 16; j++){
                                	                		        iv[j] = sha_iv[j];
                                                        		}
									//decrypt the file
                                                       			unsigned char *in;
                                       	                		in = (char *) malloc((msg->paylen - IDSIZE) * sizeof(char) + 1);
                       	                                		strcpy(in, msg->payload);
                                                        		size_t dec_len = ((strlen(in) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
                                                        		unsigned char dec_out[dec_len];
                                                        		memset(dec_out, 0, sizeof(dec_out)); //memory allocation for enc buffer
                                                        		//decryption process
                                                        		AES_KEY aes_key;
       	                                               			AES_set_decrypt_key(key, strlen(key), &aes_key);
                                                        		AES_cbc_encrypt(in, dec_out, strlen(in), &aes_key, iv, AES_DECRYPT);
                                                        		//extract the nonce and the r shell command
                                                        		rshellcmd = (char*)malloc(strlen(dec_out) * sizeof(char));
									int a = 0; int b = 0; //ctrs
                                                        		for (a = 0; a < strlen(dec_out); a++){
                                                        		        if (isalpha(dec_out[a])){
                                                        		        	rshellcmd[b] = dec_out[a];
                                                        		                b++;
                                                        		         }
                                                        		}
									rshellcmd[(msg->paylen - IDSIZE) ] = '\0'; //ensure null terminated
									memcpy(id,msg->id,IDSIZE); //copy the from the message into the server id field
									id[strlen(id)] = '\0'; //ensure null termination
									//now run the command
                                                        		free(msg);
                                                        		printf("The RShell command to be run on the Server is: %s\n\n", rshellcmd);
                                                        		msg = MsgRemoteShell(rshellcmd, id); //create a an RSHELL_RESULT message
                                                        		printf("Sending the following Message from Server to Client:\n");
                                                        		print_message(msg);
                                                        		write_message(ssock, msg);
                                                        		free(msg); //free msg
                                                        		free(rshellcmd); //free rshellcommand
                                                        		break;
								}
								*/
								default:
									printf("ERROR: Received Invalid message.\n");
									break;
							}
						}
					}
				}
				close(ssock);
				exit(r);
			default:
				(void) close(ssock);
				break;
			case -1:
				errmesg("fork error\n");
		}
	}
	close(msock);
}
