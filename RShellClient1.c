/*  
 *   RShellClient1.c	example program for CS 468
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
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

// Max ID size: 16 - 1 = 15 bytes for id, 1 for null term
#define IDSIZE 16

// Password size (in Hex)--> 20 bytes, 2 chars rep 1 byte, so 40 chars
#define PASSWDSIZE 40

// Max length of payload (2^16) = 65536
#define MAXPLSIZE 65536

// Max potential message size (2^1) + (2^2) + (2^16)
#define MAXMSGSIZE 65542

// Command size
#define MAXBUFSIZE ((MAXPLSIZE - IDSIZE) - 1)

// provided code definitions
#define LINELEN     MAXBUFSIZE
#define BUFSZ       MAXBUFSIZE
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
            printf("Received AUTH_CHLG message.\n");
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
	printf("MESSAGE--> TYPE:0x0%d   PAYLEN:%d  ID:%s   PAYLOAD:%s\n\n", msg->msgtype, msg->paylen, msg->id, msg->payload);
}

int clientsock(int UDPorTCP, const char *destination, int portN){
        struct hostent  *phe;           /* pointer to host information entry    */
        struct sockaddr_in dest_addr;   /* destination endpoint address         */
        int    sock;                    /* socket descriptor to be allocated    */

        bzero((char *)&dest_addr, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;

    	/* Set destination port number */
        dest_addr.sin_port = htons(portN);

    	/* Map host name to IPv4 address, does not work well for IPv6 */
        if ( (phe = gethostbyname(destination)) != 0 )
                bcopy(phe->h_addr, (char *)&dest_addr.sin_addr, phe->h_length);
        else if (inet_aton(destination, &(dest_addr.sin_addr))==0) /* invalid destination address */
                return -2;

	/* version that support IPv6
           else if (inet_pton(AF_INET, destination, &(dest_addr.sin_addr)) != 1)
	 */

    	/* Allocate a socket */
        sock = socket(PF_INET, UDPorTCP, 0);
        if (sock < 0)
                return -3;

    	/* Connect the socket */
        if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
                return -4;

        return sock;
}

inline int clientTCPsock(const char *destination, int portN){
  return clientsock(SOCK_STREAM, destination, portN);
}

inline int clientUDPsock(const char *destination, int portN){
  return clientsock(SOCK_DGRAM, destination, portN);
}

void usage(char *self){
	// Useage message when bad # of arguments
	fprintf(stderr, "Usage: %s <server IP> <server port number> <ID> <password> \n", self);
	exit(1);
}

void errmesg(char *msg){
	fprintf(stderr, "**** %s\n", msg);
	exit(1);
}

/*------------------------------------------------------------------------------
 * TCPrecv - read TCP socket sock w/ flag for up to buflen bytes into buf

 * return:
	>=0: number of bytes read
	<0: error
 *------------------------------------------------------------------------------*/
int TCPrecv(int sock, char *buf, int buflen, int flag){
        int inbytes, n;

        if (buflen <= 0) return 0;

  	/* first recv could be blocking */
        inbytes = 0;
        n=recv(sock, &buf[inbytes], buflen - inbytes, flag);
        if (n<=0 && n != EINTR)
                return n;

        buf[n] = 0;

        printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): first read %d bytes : `%s`\n",
                           sock, buflen, flag, n, buf);

  	/* subsequent tries for for anything left available */
        for (inbytes += n; inbytes < buflen; inbytes += n)
        {
                if (recv(sock, &buf[inbytes], buflen - inbytes, MSG_PEEK|MSG_DONTWAIT)<=0) /* no more to recv */
                        break;
                n=recv(sock, &buf[inbytes], buflen - inbytes, MSG_DONTWAIT);
                buf[n] = 0;

                printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): subsequent read %d bytes : `%s`\n",
                           sock, buflen, flag, n, &buf[inbytes]);

          if (n<=0) /* no more bytes to receive */
                break;
        };

        printf("\tTCPrecv(sock=%d, buflen=%d): read totally %d bytes : `%s`\n",
               	sock, buflen, inbytes, buf);

        return inbytes;
}

int RemoteShell(char *destination, int portN){
        char    buf[LINELEN+1];         /* buffer for one line of text  */
        char    result[resultSz+1];
        int     sock;                           /* socket descriptor, read count*/

        int     outchars, inchars;      /* characters sent and received */
        int n;

        if ((sock = clientTCPsock(destination, portN)) < 0)
                errmesg("fail to obtain TCP socket");

        while (fgets(buf, sizeof(buf), stdin))
        {
                buf[LINELEN] = '\0';    /* insure line null-terminated  */
                outchars = strlen(buf);
                if ((n=write(sock, buf, outchars))!=outchars)   /* send error */
                {
                        printf("RemoteShell(%s, %d): has %d byte send when trying to send %d bytes to RemoteShell: `%s`\n",
                           destination, portN, n, outchars, buf);

                        close(sock);
                        return -1;
                }

                printf("RemoteShell(%s, %d): sent %d bytes to RemoteShell: `%s`\n",
                           destination, portN, n, buf);

                /* Get the result */
                if ((inchars=recv(sock, result, resultSz, 0))>0) /* got some result */
		{
                        result[inchars]=0;
                        fputs(result, stdout);
                }
                if (inchars < 0)
                                errmesg("socket read failed\n");
        }

        close(sock);
        return 0;
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
    if(msg->paylen > IDSIZE){
    	if ( (n = write(sock, msg->payload, (msg->paylen - IDSIZE) )) != (msg->paylen - IDSIZE) ){
        	printf("ERROR: Has %d byte send when trying to send %d bytes for Message UserID: `%s`\n", n, (msg->paylen - IDSIZE), &msg);
        	close(sock);
        	return -1;
    	}
    }

	return 0;
}

// Recv message from socket, returns NULL if there is an error during read
Message * recv_message(int sock){
	// Create pointer to hold in the message read-in
	Message *msg = (Message*)(malloc(sizeof(Message)));

	// Read the message type
	if (recv(sock, &msg->msgtype, TYPESIZE, 0) != TYPESIZE){
		// Return NULL if there is an error
		printf("ERROR: Could not read message type.\n");
		// Free memory
		free(msg);
		// Return NULL b/c of error
		return NULL;
	}

	// Read the message length
	if (recv(sock, &msg->paylen, LENSIZE, 0) != LENSIZE){
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
    		if ( (recv(sock, &msg->id, IDSIZE, 0)) != IDSIZE ){
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
    		if ( (recv(sock, msg->payload, (msg->paylen - IDSIZE), 0)) != (msg->paylen - IDSIZE) ){
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


/*------------------------------------------------------------------------
 * main 
 *------------------------------------------------------------------------
 */
int main(int argc, char *argv[]){
	
	//command line args
	char *destination; //ip address to connect to
	int portN; //port number to connect to
	char *userid; //the user id provided
	unsigned char password[SHA_DIGEST_LENGTH * 2]; //will contain the final SHA1 has of the users password
	unsigned char tmphash[SHA_DIGEST_LENGTH]; //temp to hold sha1 of password

	unsigned char key[SHA_DIGEST_LENGTH * 2]; //will contain the sha256 hash of the password|nonce1|nonce2
	char buf[MAXBUFSIZE + 1]; //space to hold the payload		
	char id; //the user id

	//set up nonce	
	srand(2223); //initialization
        int nonce1 = (unsigned long)rand();
        int nonce2;
        char nonce1buf[12];
        char *nonce2buf;
        snprintf(nonce1buf, 12, "%d", nonce1);
        nonce1buf[strlen(nonce1buf)] = '\0';
printf("nonce 1 buf is %s\n" , nonce1buf);
	//for recv
	int inchars;
	Message *recvmsg;
	
	//sanity check for 5 args
	//The prog name and: <server IP> <server port number> <ID> <password>
	if (argc == 5){
		destination = argv[1];
		portN = atoi(argv[2]);
		userid = argv[3];
		//hash the password and store it by using openssl
		SHA_CTX ctx; //create context for sha1 hashing
		SHA1_Init(&ctx); //initialize the sha1 context
		SHA1_Update(&ctx, argv[4], strlen(argv[4])); //update to hash the user's password with the password length
		SHA1_Final(tmphash, &ctx); //finalize the hash
		int hctr = 0; //ctr for converting hash into bytes
		//reformat properly -- 2 chars at a time for 1 byte each from temp hash into hash
		for (hctr = 0; hctr < SHA_DIGEST_LENGTH; hctr++){
         	       sprintf( ((unsigned char*) &(password[ hctr * 2 ])), "%02x", tmphash[ hctr ] );
        	}
		//print the hashed password
		printf("The password \"%s\" has a SHA1 hash of \"%s\".\n\n", argv[4], password);
		//print the primary credentials
		printf("Running Client with the following credentials...\n");
		printf("    Destination: %s\n    Port: %d\n    User_ID: %s\n    Hashed_Password: %s\n\n",destination,portN,userid,password);
	}
	else {
		// Display usage information if wrong # of arguments
		usage(argv[0]);
	}
	
	int sock; //create the sock
	if ((sock = clientTCPsock(destination, portN)) < 0){
		errmesg("Failed to obtain TCP socket.");
		exit(1);
	}

	Message *msg; //create message for RSHELL_REG
	
	buf[0] = '\0'; //clear the buffer
	printf("%s\n", buf);
	
	printf("Connection established. Type a command to run on the Remote Shell...\n");
	
	while (fgets(buf, sizeof(buf), stdin)){ //get the input from the user
		if (1==1){//if (strlen(buf) > 1){ //check if buffer has anything
			printf("\n");
			buf[strlen(buf) - 1] = '\0'; //ensure buffer is null terminated
			
			//set up a random 32 bit nonce1
			//nonce1 = (unsigned long)rand();
			//snprintf(nonce1buf, 12, "%d", nonce1);

			//create message for RSHELL_REQ
			msg = malloc(sizeof(Message));
			msg->msgtype = 0x11; //set message type
			msg->paylen = IDSIZE + strlen(nonce1buf); //payload length 16 + buffer
			memcpy(msg->id,userid,(IDSIZE - 1)); //16 byte id, 15 bytes for user ID
			msg->id[strlen(userid)] = '\0'; //make sure the user ID is null-terminated
			nonce1buf[strlen(nonce1buf)] = '\0'; //make sure null-terminated
			msg->payload = nonce1buf; //send nonce over //msg->payload = buf;
			
			//send RShell Req
			printf("Sending the following Message from Client to Server:\n");
			print_message(msg);
			write_message(sock, msg);
			
			free(msg);
			
			//wait for AUTH_CHLG
			recvmsg = recv_message(sock);
			printf("Received Message from Server:\n");
			print_message(recvmsg);

			//save nonce 2
			nonce2buf = (char *) malloc((msg->paylen - IDSIZE) * sizeof(char));
			memcpy(nonce2buf, msg->payload, strlen(msg->payload));
			nonce2buf[(msg->paylen - IDSIZE) ] = '\0';
			nonce2 = atoi(msg->payload);
			//sscanf(nonce2buf, "%d", &nonce2);
		printf("nonce2buf is %s\n", nonce2buf);
		printf("nonce2 is %d\n", nonce2);	
			/*
			//encrypt nonce2+1|buf
			int tmpkey_size = (strlen(password) + strlen(nonce1buf) + strlen(nonce2buf));
			unsigned char tmpkey[tmpkey_size * 2]; //will contain the key for encrytption
			//concatenate the strings
			strcat(tmpkey, password);
			strcat(tmpkey, nonce1buf);
			strcat(tmpkey, nonce2buf);
			//SHA256 encryption
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
			//encrypt this bish
			//key iv buf
			int in_len = (strlen(buf) + strlen(nonce2buf));
			int new_nonce2 = nonce2 + 1;
			char nn2buf[MAXBUFSIZE + 1]; 
			sscanf(nn2buf, "%d", &new_nonce2);
			char input[in_len];
			strcat(input, nn2buf);
			strcat(input, buf);
			size_t enc_len = ((in_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
			unsigned char enc_out[enc_len];
			memset(enc_out, 0, sizeof(enc_out)); //memory allocation for enc buffer
			AES_KEY aes_key;
			AES_set_encrypt_key(key, strlen(key), &aes_key);
			printf("%s\n%s\n%d\n%s\n",input, enc_out,in_len,iv);
			AES_cbc_encrypt(input, enc_out, in_len, &aes_key, iv, AES_ENCRYPT);
			*/
			
			int in_len = (strlen(buf) + strlen(nonce2buf));
                        int new_nonce2 = nonce2 + 1;
                        char nn2buf[MAXBUFSIZE + 1];
			nn2buf[0] = '\0';
		printf("nn2buf is %s\n", nn2buf); 
                        snprintf(nn2buf, 12, "%d", new_nonce2);
			//sscanf(nn2buf, "%d", &new_nonce2);
                printf("nn2buf is %s\n", nn2buf);
		        char input[MAXBUFSIZE + 1];
			input[0] = '\0';
		printf("paylod is %s\n", input);
                        strcat(input, nn2buf);
		printf("paylod is %s\n", input);
                        strcat(input, buf);
		printf("paylod is %s\n", input);	
			switch(recvmsg -> msgtype){
				case AUTH_CHLG:
					//create message for command AUTH_RESP
					free(msg);
					msg = malloc(sizeof(Message));
					msg->msgtype = 0x13; //set message type
					msg->paylen = IDSIZE + strlen(input) + 1; //set payload length 16 + buffer + 1 for null terminator
					memcpy(msg->id,userid,(IDSIZE - 1));
					msg->id[strlen(userid)] = '\0'; //make sure user id is null terminated
					/*
  					enc_out[strlen(enc_out)] = '\0'; //ensure encrypted arr is null terminated
					msg->payload = enc_out; //set payload
					*/
					input[strlen(input)] = '\0';
					msg->payload = input;
				printf("paylod is %s\n", input);
					free(recvmsg); //free recvmsg
				
					//send AUTH_RESP
					printf("Sending the following Message from Client to Server:\n");
					print_message(msg);
					write_message(sock, msg);
					
					//now wait for AUTH_SUCCESS / AUTH_FAIL
					recvmsg = recv_message(sock);
					printf("Received Message from Server:\n");
					print_message(recvmsg); printf("error!!");
					
					switch(recvmsg -> msgtype){
						case AUTH_SUCCESS:
							free(recvmsg); //free recvmsg
							printf("Authentication Success!\n");
							//get the command exec result
							recvmsg = recv_message(sock);
							printf("Received Message from Server:\n");
							print_message(recvmsg); printf("error!!");
							if(recvmsg -> msgtype == RSHELL_RESULT){
								//get and print the result
								if(recvmsg->payload != NULL){
                                                                	printf("\nThe result of the command was:\n%s\n\n", recvmsg->payload);
								}
								else {
                                                                	//command not found
                                                                	printf("\nThe result of the command was:\ncommand not found\n\n");
                                                                }
							}
							else {
								printf("ERROR: Received Invalid message.\n");
							}
							break;
						case AUTH_FAIL:
							free(recvmsg); //free recvmsg
							printf("Authentication Failed!\n");
							exit(1);
							break;
						default:
							printf("ERROR: Received Invalid message.\n");
							break;
					}
					break;
				case RSHELL_RESULT:
					//get and print the result
					if(recvmsg->payload != NULL){
						printf("\nThe result of the command was:\n%s\n\n", recvmsg->payload);
					}
					else {
						//command not found
						printf("\nThe result of the command was:\ncommand not found\n\n");
					}
					break;
				default:
					printf("ERROR: Received Invalid message.\n");
					break;
			}
			
			buf[0] = '\0'; //clear the buffer
			
			//print seperating stars
			printf("**********************************************************************\n\n");

			//ask for another command
			printf("Type another command to run on the Remote Shell...\n");
		}
		else {
			exit(0); //quit program
		}
	}
	
	exit(0); //terminate
}
