// -------------------------------------------------------------------------------
// RPLMaster
// Version: 1.5
// Author: ouned
// License: GPLv3
// -------------------------------------------------------------------------------
#include "master.h"

SOCKET srvsock, querysock;
struct sockaddr_in srvip;
conf_t conf;
srv_t servers[MAX_SERVERS];
reqip_t ipsec[MAX_REQUEST_IPS_SECOND];
int ipsecLen;
time_t nextSave;
char fileBackup[512];

// stats vars
time_t stat_startup;
uint64_t stat_reqs;

int main(int argc, char *argv[]) {
	time_t timer = time(0);
#ifdef WIN32
	WSADATA wsaData;
	int err;
#endif
	struct timeval tv;

	if (argc < 3) {
		println(MSG_INFO, "Usage: "DEFAULT_EXE_NAME" <configfile> <backupfile>");
		println(MSG_INFO, "Example: "DEFAULT_EXE_NAME" rplmaster.cfg rplmaster.bak");
		return 0;
	}
	strncpy(fileBackup, argv[2], sizeof(fileBackup));

	println(MSG_INFO, "-----------------------------------------");
	println(MSG_INFO, "RPLMaster v"STR_VERSION"");
	println(MSG_INFO, "Author: ouned");
	println(MSG_INFO, "-----------------------------------------");

	println(MSG_INFO, "parsing config file %s...", argv[1]);
	if (ini_parse(argv[1], ParseConfig, &conf)) {
		println(MSG_ERROR, "could not read config file.");
		return 1;
	}

#ifdef WIN32
	println(MSG_DEBUG, "starting up winsock 2.2...");
	err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != 0) {
		println(MSG_ERROR, "WSAStartup failed with error: %i", err);
		return 1;
	}
#endif

	// prepare sockets
	println(MSG_DEBUG, "creating sockets...");
	srvsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	querysock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (srvsock == INVALID_SOCKET || querysock == INVALID_SOCKET) {
		println(MSG_ERROR, "socket creation failed.");
		return 1;
	}

	// timeout
	tv.tv_sec = 0;
	tv.tv_usec = RECV_TIMEOUT * 1000;

	// set timeout
	if (setsockopt(srvsock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) != 0) {
		println(MSG_ERROR, "setsockopt failed.");
		return 1;
	}

	// set timeout
	if (setsockopt(querysock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) != 0) {
		println(MSG_ERROR, "setsockopt failed.");
		return 1;
	}

	// bind to port
	println(MSG_DEBUG, "starting to listen on port %i...", conf.port);
	srvip.sin_family = AF_INET;
	srvip.sin_addr.s_addr = htonl(INADDR_ANY);
	srvip.sin_port = htons(conf.port);
	if (bind(srvsock, (const struct sockaddr *)&srvip, sizeof(srvip)) != 0) {
		println(MSG_ERROR, "binding socket to port %i failed. Already in use?", conf.port);
		return 1;
	}

	// init random number generator
	srand((unsigned int)time(0));

	// restore servers from backup file
	RestoreServerState();

	// init backup file timer
	nextSave = time(0) + conf.backupfile;

	stat_startup = time(0);
	println(MSG_INFO, "master is now ready and running on port %i", conf.port);
	TimerEvent();

	while (1) {
		byte data[MAX_RECVLEN + 1];
		fd_set fds;
		struct sockaddr_in from;
		int len, ret_val;
		socklen_t fromlen;

		// prepare data for select call
		FD_ZERO(&fds);
		FD_SET(srvsock, &fds);
		FD_SET(querysock, &fds);

		// timeout
		tv.tv_sec = 0;
		tv.tv_usec = RECV_TIMEOUT * 1000;

		ret_val = select(FD_SETSIZE, &fds, NULL, NULL, &tv);
		if (ret_val > 0) {
			for (SOCKET sock = srvsock, i = 0; i < 2; sock = querysock, i++) {
				if (!FD_ISSET(sock, &fds))
					continue;

				fromlen = sizeof(from);
				len = recvfrom(sock, (char *)data, MAX_RECVLEN, 0, (struct sockaddr *)&from, &fromlen);

				// packets & firewall
				if (len > 0) {
					int found = 0;

					for (i = 0; i < ipsecLen; i++) {
						if (ipsec[i].ip.s_addr == from.sin_addr.s_addr) {
							ipsec[i].numreq++;

							if (ipsec[i].numreq <= conf.maxpacketsip) {
								PacketReceived(sock, data, len, &from);
							} else {
								println(MSG_DEBUG, "blocked packet from %s (maximum reached)", addrstr(&from));
							}

							found = 1;
							break;
						}
					}

					if (!found) {
						if (ipsecLen < MAX_REQUEST_IPS_SECOND) {
							ipsec[ipsecLen].ip = from.sin_addr;
							ipsec[ipsecLen].numreq = 1;
							ipsecLen++;

							PacketReceived(sock, data, len, &from);
						}
					}
				}
			}
		}

		// timer
		if (time(0) - timer >= TIMER_LOOP) {
			TimerEvent();
		}
		timer = time(0);
	}

	println(MSG_INFO, "shutting down...");
	closesocket(srvsock);
	closesocket(querysock);
#ifdef WIN32
	WSACleanup();
#endif

	return 0;
}

int ParseConfig(void *user, const char *section, const char *name, const char *value) {
	conf_t *cfg = (conf_t*)user;

	if (!strcmp(section, "RPLMaster")) {
		if (!strcmp(name, "port")) {
			cfg->port = atoi(value);
		} else if (!strcmp(name, "request")) {
			cfg->request = atoi(value);
		} else if (!strcmp(name, "timeout")) {
			cfg->timeout = atoi(value);
		} else if (!strcmp(name, "debug")) {
			cfg->debug = atoi(value);
		} else if (!strcmp(name, "disable")) {
			cfg->disable = atoi(value);
		} else if (!strcmp(name, "maxserversip")) {
			cfg->maxserversip = atoi(value);
		} else if (!strcmp(name, "maxpacketsip")) {
			cfg->maxpacketsip = atoi(value);
		} else if (!strcmp(name, "backupfile")) {
			cfg->backupfile = atoi(value);
		} else if (!strcmp(name, "stef")) {
			cfg->stef = atoi(value);
		} else if (!strcmp(name, "q2")) {
			cfg->q2 = atoi(value);
		} else if (!strcmp(name, "fallbackProtocol")) {
			cfg->fallbackProtocol = atoi(value);
		}
	} else if (!strncmp(section, "SourceMaster", 12)) {
		int srvNum = atoi(section + 12);

		if (!strcmp(name, "active")) {
			cfg->srcmasters[srvNum].active = atoi(value);
		} else if (!strcmp(name, "host")) {
			strncpy(cfg->srcmasters[srvNum].host, value, sizeof(cfg->srcmasters[0].host)-1);
		} else if (!strcmp(name, "port")) {
			cfg->srcmasters[srvNum].port = atoi(value);
		} else if (!strcmp(name, "protocols")) {
			int num = 0;
			char *t;

            strtok((char *)value, ",");
			while ((t = strtok(NULL, ",")) != NULL) {
				cfg->srcmasters[srvNum].protocols[num] = atoi(t);
				num++;
			}
			cfg->srcmasters[srvNum].protocols[num] = atoi(value);
		} else if (!strcmp(name, "interval")) {
			cfg->srcmasters[srvNum].interval = atoi(value);
		} else if (!strcmp(name, "getserversKeywords")) {
			strncpy(cfg->srcmasters[srvNum].getserversKeywords, value, sizeof(cfg->srcmasters[srvNum].getserversKeywords)-1);
		}
	}

	return 1;
}

void PacketReceived(SOCKET socket, byte *data, int len, struct sockaddr_in *from) {
	char cmd[64], arg1[64], arg2[64];

	data[len] = 0;

	// check for \xFF\xFF\xFF\xFF
	if (!(len > 4) || memcmp(data, "\xFF\xFF\xFF\xFF", 4)) {
		return;
	}

	*cmd = 0; *arg1 = 0; *arg2 = 0; // Valgrind detects unconditional jumps for strncmp on optimized builds (gcc and clang)
	TokenizeCommandline((const char *)data + 4, cmd, sizeof(cmd), arg1, sizeof(arg1), arg2, sizeof(arg2), NULL);

	// only "getserversResponse" because dpmaster returns bad data
	if (!strncmp(cmd, "getserversResponse", sizeof("getserversResponse")-1)) {
		srcmaster_t *srcmaster = NULL;
		int scanpos;
		int i;
		int numServers = 0;

		if (socket == querysock) {
			println(MSG_WARNING, "%s sent getserversResponse to the query socket", addrstr(from));
			return;
		}

		for (i = 0; i < MAX_SOURCE_MASTERS; i++) {
			if (conf.srcmasters[i].active && !addrcmp(&conf.srcmasters[i].addr, from)) {
				srcmaster = &conf.srcmasters[i];
				break;
			}
		}

		// some sith tried to inject fake servers
		if (!srcmaster) {
			println(MSG_WARNING, "%s tried to inject fake servers", addrstr(from));
			return;
		}

		// 24B (\xFF\xFF\xFF\xFFgetserversResponse\n\x00) + 1B '\' + 3B (EO(T|F))
		if (len <= sizeof("getserversResponse\n") + 1 + 3) {
			return;
		}

		// search for the first '\' ... can't set to byte 24 because dpmaster is returning malformed data
		scanpos = 0;
		while (scanpos < len && data[scanpos] != '\\')
			scanpos++;

		while (data[scanpos] == '\\') {
			struct sockaddr_in addr;
			srv_t *srv = NULL;

			if (conf.stef && len - scanpos - 1 < 12) {
				// STEF: at least 8B for the ip and 4B for the port should be left
				break;
			}
			else if (len - scanpos - 1 < 6) {
				// at least 4B for the ip and 2B for the port should be left
				break;
			}

			// dpmaster bug 2... returns EOT\x00\x00\x00 on the end
			if (len - scanpos - 1 == 6 && data[scanpos + 1] == 'E' && data[scanpos + 2] == 'O' && data[scanpos + 3] == 'T') {
				break;
			}

			addr.sin_family = AF_INET;

			if (conf.stef) {
				// STEF has ips and ports encoded in hex, so we parse the values here and store them in the same format
				// used by ioq3, jk2, ...
				char hexValue[3] = { 0 };
				for ( i = 0; i < 6; i++ ) {
					memcpy( hexValue, &data[scanpos+1+(i*2)], 2 );
					data[scanpos+1+i] = (unsigned char)strtoul( hexValue, NULL, 16 );
				}
			}

			addr.sin_addr.s_addr = *(uint32_t *)(&data[scanpos + 1]);
			addr.sin_port = *(uint16_t *)(&data[scanpos + 5]);

			for (i = 0; i < MAX_SERVERS; i++) {
				if (servers[i].state != STATE_UNUSED && !addrcmp(&servers[i].addr, &addr)) {
					srv = &servers[i];
					break;
				}
			}

			// add this server as a new one
			if (!srv) {
				int numip = NumServersIPAddr(&addr);

				// maximum number of servers for this ip reached
				if (numip >= conf.maxserversip) {
					println(MSG_WARNING, "can not add server %s maximum servers per ip reached", addrstr(&addr));
				}

				for (i = 0; i < MAX_SERVERS; i++) {
					if (servers[i].state == STATE_UNUSED) {
						int random = rand() % 11; // 0 to 10

						servers[i].state = STATE_DISABLED;
						servers[i].protocol = 0;
						servers[i].addr = addr;
						servers[i].nextReq = time(0) + random; // not all at the same time
						servers[i].disable = time(0) + conf.disable + random;
						servers[i].timeout = time(0) + conf.timeout + random;
						break;
					}
				}
			}

			numServers++;
			if (conf.stef) scanpos += 13; // 8B (IP) + 4B (Port) + 1B (\)
			else scanpos += 7; // 4B (IP) + 2B (Port) + 1B (\)
		}

		println(MSG_DEBUG, "parsed %i servers from %s", numServers, srcmaster->host);
	} else if ( conf.q2 == 1 && !strncmp(cmd, "print\n", 6) ) {
		if (socket == srvsock) {
			println(MSG_WARNING, "%s sent infoResponse to the server socket", addrstr(from));
			return;
		}

		char *info = data;
		while ( *info && *info != '\\' )
			info++;

		if ( *info )
		{
			int i;
			for (i = 0; i < MAX_SERVERS; i++) {
				if (servers[i].state != STATE_UNUSED && !addrcmp(&servers[i].addr, from)) {
					int protocol = atoi(Info_ValueForKey(info, "protocol"));

					if (protocol == 0 && conf.fallbackProtocol) {
						protocol = conf.fallbackProtocol;
					} else if (protocol <= 0) {
						println(MSG_DEBUG, "invalid infoResponse from %s", addrstr(from));
						return;
					}

					println(MSG_DEBUG, "received status response from %s", addrstr(from));

					servers[i].state = STATE_ACTIVE;
					servers[i].nextReq = time(0) + conf.request;
					servers[i].disable = time(0) + conf.disable;
					servers[i].timeout = time(0) + conf.timeout;
					servers[i].protocol = protocol;
					break;
				}
			}
		}
	} else if ( conf.q2 == 1 && !strcmp(cmd, "ping") ) {
		if (socket == querysock) {
			println(MSG_WARNING, "%s sent ping to the query socket", addrstr(from));
			return;
		}

		srv_t *srv = NULL;
		int i;

		for (i = 0; i < MAX_SERVERS; i++) {
			if (servers[i].state != STATE_UNUSED && !addrcmp(&servers[i].addr, from)) {
				srv = &servers[i];
				break;
			}
		}

		println(MSG_DEBUG, "received ping from %s", addrstr(from));

		if (!srv) {
			int numip = NumServersIPAddr(from);

			// maximum number of servers for this ip reached
			if (numip >= conf.maxserversip) {
				println(MSG_WARNING, "can not add server %s maximum per ip reached", addrstr(from));
			}

			for (i = 0; i < MAX_SERVERS; i++) {
				if (servers[i].state == STATE_UNUSED) {
					servers[i].state = STATE_DISABLED;
					servers[i].protocol = 0;
					servers[i].addr = *from;
					servers[i].nextReq = 0; // instantly
					servers[i].disable = time(0) + conf.disable;
					servers[i].timeout = time(0) + conf.timeout;

					srv = &servers[i];
					break;
				}
			}
		}

		if (srv) {
			srv->lastheartbeat = time(0);
		}
	} else if ( (conf.stef == 1 && !strcmp(cmd, "infoResponse")) ||
	            (!strncmp(cmd, "infoResponse\n", sizeof("infoResponse\n") - 1)) ) {
		int i;

		if (socket == srvsock) {
			println(MSG_WARNING, "%s sent infoResponse to the server socket", addrstr(from));
			return;
		}

		for (i = 0; i < MAX_SERVERS; i++) {
			if (servers[i].state != STATE_UNUSED && !addrcmp(&servers[i].addr, from)) {
				char *info = data + sizeof("\xFF\xFF\xFF\xFFinfoResponse") - 1;
				int protocol;

				while ( *info && *info <= ' ' ) // Skip any amount of whitespace, just like the TokenizeString function of the game would
					info++;

				if ( conf.stef == 1 ) {
					// STEF has its InfoString surrounded by '"' to be used with Cmd_* functions, so just cut it away
					char *end = &info[strlen(info)-1];
					while ( *info == '"' )
						info++;

					while ( end > info && *end == '"' )
						*(end--) = 0;
				}

				protocol = atoi(Info_ValueForKey(info, "protocol"));

				if (protocol == 0 && conf.fallbackProtocol) {
					protocol = conf.fallbackProtocol;
				} else if (protocol <= 0) {
					println(MSG_DEBUG, "invalid infoResponse from %s", addrstr(from));
					return;
				}

				println(MSG_DEBUG, "received status response from %s", addrstr(from));

				servers[i].state = STATE_ACTIVE;
				servers[i].nextReq = time(0) + conf.request;
				servers[i].disable = time(0) + conf.disable;
				servers[i].timeout = time(0) + conf.timeout;
				servers[i].protocol = protocol;
				break;
			}
		}
	} else if (!strcmp(cmd, "getservers")) {
		//byte resp[sizeof("\xFF\xFF\xFF\xFFgetserversResponse\n") + MAX_SERVERS_PER_PACKET * 7 + 4];
		byte resp[sizeof("\xFF\xFF\xFF\xFFgetserversResponse\n") + MAX_SERVERS_PER_PACKET * 13 + 4 ];
		int resplen;
		int protocol;
		int i, numsrvsresp = 0, numsrvs = 0;

		if (socket == querysock) {
			println(MSG_WARNING, "%s sent getservers request to the query socket", addrstr(from));
			return;
		}

		protocol = atoi(arg1);
		if (protocol <= 0) {
			println(MSG_DEBUG, "invalid getservers request from %s", addrstr(from));
			return;
		}

		if (conf.stef == 1) {
			strcpy(resp, "\xFF\xFF\xFF\xFFgetserversResponse ");
		} else {
			strcpy(resp, "\xFF\xFF\xFF\xFFgetserversResponse\n");
		}
		resplen = sizeof("\xFF\xFF\xFF\xFFgetserversResponse\n") - 1;
		for (i = 0; i < MAX_SERVERS; i++) {
			if (servers[i].state != STATE_ACTIVE || servers[i].protocol != protocol) {
				continue;
			}

			if (!strcmp(arg2, "heartbeaters") && (time(0) - servers[i].lastheartbeat) > 600) {
				continue;
			}

			// reached MAX_SERVERS_PER_PACKET limit but have more servers
			// send out data and prepare another packet
			if (numsrvsresp >= MAX_SERVERS_PER_PACKET) {
				resp[resplen++] = (byte)'\\';
				resp[resplen++] = 'E'; resp[resplen++] = 'O';
				if (conf.stef) resp[resplen++] = 'F';
				else resp[resplen++] = 'T';
				sendto(srvsock, (const char *)resp, resplen, 0, (const struct sockaddr *)from, sizeof(struct sockaddr_in));

				numsrvsresp = 0;
				resplen = sizeof("\xFF\xFF\xFF\xFFgetserversResponse\n") - 1;
			}

			resp[resplen++] = (byte)'\\';

			if (conf.stef) {
				sprintf(&resp[resplen], "%x%x", ntohl(servers[i].addr.sin_addr.s_addr), ntohs(servers[i].addr.sin_port));
			} else {
				*(uint32_t *)(&resp[resplen]) = (uint32_t)servers[i].addr.sin_addr.s_addr;
				*(uint16_t *)(&resp[resplen + 4]) = (uint16_t)servers[i].addr.sin_port;
			}

			if (conf.stef) resplen += 12; // 8B (IP) + 2B (Port)
			else resplen += 6; // 4B (IP) + 2B (Port)
			numsrvsresp++, numsrvs++;
		}

		resp[resplen++] = (byte)'\\';
		resp[resplen++] = 'E'; resp[resplen++] = 'O'; resp[resplen++] = 'T';

		stat_reqs++;
		println(MSG_DEBUG, "%s requested servers for protocol %i (%i servers sent)", addrstr(from), protocol, numsrvs);
		sendto(srvsock, (const char *)resp, resplen, 0, (const struct sockaddr *)from, sizeof(struct sockaddr_in));
	} else if (!strcmp(cmd, "heartbeat")) {
		srv_t *srv = NULL;
		int i;

		if (socket == querysock) {
			println(MSG_WARNING, "%s sent heartbeat to the query socket", addrstr(from));
			return;
		}

		for (i = 0; i < MAX_SERVERS; i++) {
			if (servers[i].state != STATE_UNUSED && !addrcmp(&servers[i].addr, from)) {
				srv = &servers[i];
				break;
			}
		}

		println(MSG_DEBUG, "received heartbeat from %s", addrstr(from));

		if (!srv) {
			int numip = NumServersIPAddr(from);

			// maximum number of servers for this ip reached
			if (numip >= conf.maxserversip) {
				println(MSG_WARNING, "can not add server %s maximum per ip reached", addrstr(from));
			}

			for (i = 0; i < MAX_SERVERS; i++) {
				if (servers[i].state == STATE_UNUSED) {
					servers[i].state = STATE_DISABLED;
					servers[i].protocol = 0;
					servers[i].addr = *from;
					servers[i].nextReq = 0; // instantly
					servers[i].disable = time(0) + conf.disable;
					servers[i].timeout = time(0) + conf.timeout;

					srv = &servers[i];
					break;
				}
			}
		}

		if (srv) {
			srv->lastheartbeat = time(0);
		}
	} else if (!strcmp(cmd, "master")) {
		if (socket == querysock) {
			println(MSG_WARNING, "%s sent master info request to the query socket", addrstr(from));
			return;
		}

		println(MSG_DEBUG, "%s requested master information", addrstr(from));
		sendto(srvsock, STR_MASTER_INFO, sizeof(STR_MASTER_INFO), 0, (const struct sockaddr *)from, sizeof(struct sockaddr_in));
	} else if (!strcmp(cmd, "stats")) {
		if (socket == querysock) {
			println(MSG_WARNING, "%s sent stats info request to the query socket", addrstr(from));
			return;
		}

		if (!strcmp(arg1, "version")) {
			sendto(srvsock, STR_VERSION, sizeof(STR_VERSION), 0, (const struct sockaddr *)from, sizeof(struct sockaddr_in));
		} else if (!strcmp(arg1, "startup")) {
			char resp[16];
			sprintf(resp, "%"PRIu64, (uint64_t)stat_startup);
			sendto(srvsock, resp, (int)strlen(resp) + 1, 0, (const struct sockaddr *)from, sizeof(struct sockaddr_in));
		} else if (!strcmp(arg1, "reqs")) {
			char resp[16];
			sprintf(resp, "%"PRIu64, (uint64_t)stat_reqs);
			sendto(srvsock, resp, (int)strlen(resp) + 1, 0, (const struct sockaddr *)from, sizeof(struct sockaddr_in));
		}
	} else {
		println(MSG_DEBUG, "unknown packet received from %s", addrstr(from));
	}
}

void TimerEvent() {
	int i, j;

	// send requests to source masters
	for (i = 0; i < MAX_SOURCE_MASTERS; i++) {
		struct hostent *host;

		if (conf.srcmasters[i].active == 0) {
			continue;
		}

		if (time(0) < conf.srcmasters[i].nextReq) {
			continue;
		}
		conf.srcmasters[i].nextReq = time(0) + conf.srcmasters[i].interval;

		// host needs to be resolved each time to support dyndns
		host = gethostbyname(conf.srcmasters[i].host);
		if (host == NULL || host->h_addr_list[0] == NULL) {
			println(MSG_WARNING, "failed to resolve hostname %s", conf.srcmasters[i].host);
			continue;
		}

		memcpy(&conf.srcmasters[i].addr.sin_addr, host->h_addr_list[0], host->h_length);
		conf.srcmasters[i].addr.sin_family = AF_INET;
		conf.srcmasters[i].addr.sin_port = htons(conf.srcmasters[i].port);

		for (j = 0; j < MAX_PROTOCOLS; j++) {
			char req[64 + sizeof(conf.srcmasters[i].getserversKeywords)];

			if (conf.srcmasters[i].protocols[j] == 0) {
				continue;
			}

			println(MSG_DEBUG, "requesting servers from %s protocol %i...", conf.srcmasters[i].host, conf.srcmasters[i].protocols[j]);

			if ( conf.stef && *conf.srcmasters[i].getserversKeywords ) { // Let the config set custom keywords
				sprintf( req, "\xFF\xFF\xFF\xFFgetservers %i %s", conf.srcmasters[i].protocols[j], conf.srcmasters[i].getserversKeywords );
			} else if ( conf.stef ) { // STEF defaults to "empty full"
				sprintf(req, "\xFF\xFF\xFF\xFFgetservers %i empty full", conf.srcmasters[i].protocols[j]);
			} else {
				sprintf(req, "\xFF\xFF\xFF\xFFgetservers %i", conf.srcmasters[i].protocols[j]);
			}

			sendto(srvsock, req, (int)strlen(req), 0, (const struct sockaddr *)&conf.srcmasters[i].addr, sizeof(conf.srcmasters[i].addr));
		}
	}

	// request info from servers and disable, delete timed out servers
	for (i = 0; i < MAX_SERVERS; i++) {
		if (servers[i].state == STATE_UNUSED) {
			continue;
		}

		if (servers[i].disable <= time(0) && servers[i].state == STATE_ACTIVE) {
			println(MSG_DEBUG, "server %s disabled", addrstr(&servers[i].addr));
			servers[i].state = STATE_DISABLED;
		}

		if (servers[i].timeout <= time(0) && servers[i].state == STATE_DISABLED) {
			println(MSG_DEBUG, "server %s timed out", addrstr(&servers[i].addr));
			memset(&servers[i], 0, sizeof(servers[i]));
			continue;
		}

		if (servers[i].nextReq <= time(0)) {
			println(MSG_DEBUG, "requesting info from %s...", addrstr(&servers[i].addr));
			if ( conf.q2 )
				sendto(querysock, "\xFF\xFF\xFF\xFFstatus", sizeof("\xFF\xFF\xFF\xFFstatus"), 0, (const struct sockaddr *)&servers[i].addr, sizeof(servers[i].addr));
			else
				sendto(querysock, "\xFF\xFF\xFF\xFFgetinfo", sizeof("\xFF\xFF\xFF\xFFgetinfo"), 0, (const struct sockaddr *)&servers[i].addr, sizeof(servers[i].addr));
			servers[i].nextReq = time(0) + conf.request;
		}
	}

	// reset firewall
	memset(ipsec, 0, sizeof(ipsec));
	ipsecLen = 0;

	// backup file
	if (nextSave <= time(0) && conf.backupfile > 0) {
		SaveServerState();
		nextSave = time(0) + conf.backupfile;
	}
}

void SaveServerState() {
	FILE *f;

	if ((f = fopen(fileBackup, "w")) == NULL) {
		println(MSG_ERROR, "could not write backup file (%s)", fileBackup);
		return;
	}

	fwrite(servers, sizeof(char), sizeof(servers), f);
	fclose(f);

	println(MSG_DEBUG, "saved %u bytes to %s", sizeof(servers), fileBackup);
}

void RestoreServerState() {
	FILE *f;
	int i;

	if ((f = fopen(fileBackup, "r")) == NULL) {
		println(MSG_INFO, "backup file (%s) not restored", fileBackup);
		return;
	}

	fread(servers, sizeof(char), sizeof(servers), f);
	fclose(f);

	// reset all the timers
	for (i = 0; i < MAX_SERVERS; i++) {
		int random;

		if (servers[i].state == STATE_UNUSED) {
			continue;
		}

		random = rand() % 11; // 0 to 10

		servers[i].nextReq = time(0) + random;
		servers[i].disable = time(0) + conf.disable + random;
		servers[i].timeout = time(0) + conf.timeout + random;
	}

	println(MSG_INFO, "restored %u bytes from %s", sizeof(servers), fileBackup);
}

// Info_ValueForKey
// stolen from quake 3 source
char *Info_ValueForKey(const char *s, const char *key) {
	char pkey[MAX_RECVLEN];
	static char value[2][MAX_RECVLEN];
	static int valueindex = 0;
	char	*o;

	if (!s || !key) {
		return "";
	}

	if (strlen(s) >= MAX_RECVLEN) {
		return "";
	}

	valueindex ^= 1;
	if (*s == '\\')
		s++;

	while (1) {
		o = pkey;
		while (*s != '\\') {
			if (!*s)
				return "";

			*o++ = *s++;
		}

		*o = 0;
		s++;
		o = value[valueindex];
		while (*s != '\\' && *s) {
			*o++ = *s++;
		}

		*o = 0;

		if (!_stricmp(key, pkey)) {
			return value[valueindex];
		}

		if (!*s)
			break;
		s++;
	}

	return "";
}

void TokenizeCommandline(const char *line, char *cmd, size_t cmdsize, ...) {
	size_t i;
	va_list vl;
	char *currarg = cmd;
	size_t currargsize = cmdsize;
	size_t currarglen = 0;
	int quot = 0;

	va_start(vl, cmdsize);
	for (i = 0; i < strlen(line); i++) {
		if ((!quot && line[i] == ' ') || (quot && line[i] == '"')) {
			currarg[currarglen++] = 0;

			currarg = va_arg(vl, char *);
			if (currarg) {
				currargsize = va_arg(vl, size_t);

				if (line[i] == '"')
					i++;

				currarglen = 0;
				continue;
			} else {
				break;
			}
		} else if (!quot && line[i] == '"') {
			quot = 1;
			continue;
		}

		if (currargsize > currarglen + 1)
			currarg[currarglen++] = line[i];
	}

	if (currarg)
		currarg[currarglen++] = 0;

	// ensure all arguments (even unused ones) are zero terminated
	while (currarg && (currarg = va_arg(vl, char *))) {
		currarg[0] = 0;
		va_arg(vl, size_t);
	}

	va_end(vl);
}

int addrcmp(struct sockaddr_in *adr1, struct sockaddr_in *adr2) {
	if (adr1->sin_addr.s_addr == adr2->sin_addr.s_addr && adr1->sin_port == adr2->sin_port) {
		return 0;
	} else {
		return 1;
	}
}

const char *addrstr(const struct sockaddr_in *addr) {
	static char addrstr[50];

	sprintf(addrstr, "%s:%u", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

	return addrstr;
}

int NumServersIPAddr(struct sockaddr_in *addr) {
	int num = 0;
	int i;

	for (i = 0; i < MAX_SERVERS; i++) {
		if (servers[i].state == STATE_UNUSED) {
			continue;
		}

		if (servers[i].addr.sin_addr.s_addr == addr->sin_addr.s_addr) {
			num++;
		}
	}

	return num;
}

int println(msg_t type, const char *fmt, ...) {
	va_list list;
	int i;

	if (type == MSG_WARNING) {
		printf("WARNING: ");
	} else if (type == MSG_ERROR) {
		printf("ERROR: ");
	} else if (type == MSG_DEBUG && !conf.debug) {
		return -1;
	}

	va_start(list, fmt);
	i = vfprintf(stdout, fmt, list);
	va_end(list);

	printf("\n");

	return i;
}
