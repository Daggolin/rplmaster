// -------------------------------------------------------------------------------
// RPLMaster
// Version: 1.3
// Author: ouned
// License: GPLv3
// -------------------------------------------------------------------------------
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include "ini.h"
#ifdef WIN32
#	include <winsock2.h>
#	pragma comment(lib, "ws2_32.lib")
#else
#	include <strings.h>
#	include <sys/types.h>
#	include <sys/time.h>
#	include <netdb.h>
#	include <sys/socket.h>
#	include <netinet/in.h>
#	include <unistd.h>
#	include <netinet/in.h>
#	include <arpa/inet.h>
#	include <sys/select.h>
#	include <fcntl.h>
#endif

// ---------------------------------------------------- SETTINGS ----------------------------------------------------
#define STR_VERSION "1.3"

#define RECV_TIMEOUT 500										// should not be changed
#define TIMER_LOOP 1											// should not be changed

#define MAX_RECVLEN 2048										// max. length in bytes of an incoming udp datagram
#define MAX_SOURCE_MASTERS 16									// max. supported SourceMasters
#define MAX_PROTOCOLS 16										// max. supported protocols per SourceMaster
#define MAX_SERVERS 8192										// max. free server slots (for all protocols together)
#define MAX_REQUEST_IPS_SECOND 8192								// max. number of different IP's per second
#define MAX_SERVERS_PER_PACKET 256								// max. servers per packet in a server response packet

// ------------------------------------------------------------------------------------------------------------------

typedef uint8_t byte;
#define STR_MASTER_INFO "RPLMaster " STR_VERSION "\n"

#ifdef WIN32
#	define DEFAULT_EXE_NAME "rplmaster.exe"
	typedef int socklen_t;
#else
#	define DEFAULT_EXE_NAME "rplmaster"
#	define INVALID_SOCKET -1
#	define _stricmp strcasecmp
	typedef int SOCKET;
#	define closesocket close
#endif

typedef enum {
	MSG_DEBUG,
	MSG_INFO,
	MSG_WARNING,
	MSG_ERROR
} msg_t;

typedef enum {
	STATE_UNUSED,
	STATE_DISABLED,
	STATE_ACTIVE,
} srvstate_t;

typedef struct {
	int active;
	char host[128];
	struct sockaddr_in addr;
	int port;
	int protocols[MAX_PROTOCOLS];
	int interval;
	time_t nextReq;
	char getserversKeywords[64];
} srcmaster_t;

typedef struct {
	srvstate_t state;
	struct sockaddr_in addr;
	int protocol;
	time_t nextReq;
	time_t disable;
	time_t timeout;
	time_t lastheartbeat;
} srv_t;

typedef struct {
	int port;
	int request;
	int timeout;
	int debug;
	int disable;
	int maxserversip;
	int maxpacketsip;
	int backupfile;
	int stef;
	int q2;
	int fallbackProtocol;
	srcmaster_t srcmasters[MAX_SOURCE_MASTERS];
} conf_t;

typedef struct {
	struct in_addr ip;
	int numreq;
} reqip_t;

void PacketReceived(SOCKET socket, char *data, int len, struct sockaddr_in *from);
int ParseConfig(void *user, const char *section, const char *name, const char *value);
void TimerEvent();
char *Info_ValueForKey(const char *s, const char *key);
void TokenizeCommandline(const char *line, char *cmd, size_t cmdsize, ...);
int addrcmp(struct sockaddr_in *adr1, struct sockaddr_in *adr2);
int println(msg_t type, const char *fmt, ...);
const char *addrstr(const struct sockaddr_in *addr);
int NumServersIPAddr(struct sockaddr_in *addr);
void SaveServerState();
void RestoreServerState();
