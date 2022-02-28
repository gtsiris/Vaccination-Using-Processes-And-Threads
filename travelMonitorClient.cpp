#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "struct_Monitor.h"
#include "class_Travel_Request.h"
#include "class_Country.h"
#include "class_Virus.h"
#include "struct_List.h"

#define END_OF_MESSAGE "#"  /* Let receiver know that message has been completed */
#define ACK "@"  /* Follow up each message with acknowledgement */
#define STOP "$"  /* Doesn't require ACK. Signifies change of direction in communication */
#define OK 0
#define ERROR !OK
#define MINIMUM_SOCKET_BUFFER_SIZE 1  /* Socket buffer must be atleast 1 byte */
#define MINIMUM_CYCLIC_BUFFER_SIZE 1  /* Cyclic buffer must be atleast 1 byte */
#define MAX_HOSTNAME_LENGTH 1024
#define MIN_PORT 49152  /* Non-reserved ports */
#define MAX_PORT 65535

using namespace std;

bool Configure(const int& argc, char** argv, unsigned int& numMonitors, unsigned int& socketBufferSize, unsigned int& cyclicBufferSize, unsigned int& sizeOfBloom, string& inputDir, unsigned int& numThreads);

void PrintProperExec();

string GetIpAddress();

int GetRandomPort();

int BindOnPort(const int& socketFD, const string& IP, const int& port);

bool CreateSockets(const unsigned int& numMonitors, list& monitors);

void DeleteSockets(const unsigned int& numMonitors, list& monitors);

bool AcceptConnections(const unsigned int& numMonitors, list& monitors);

void CloseConnections(const unsigned int& numMonitors, list& monitors);

bool RoundRobin(const unsigned int& numMonitors, const string& inputDir, list& monitors);

bool CreateMonitors(const unsigned int& numMonitors, const unsigned int& socketBufferSize, const unsigned int& cyclicBufferSize, const unsigned int& sizeOfBloom, const string& inputDir, const unsigned int& numThreads, list& monitors);

bool ReceiveBloomFilters(const unsigned int& numMonitors, const unsigned int& bufferSize, const unsigned int& sizeOfBloom, list& monitors, list& viruses);

bool SendMessageReceiveACK(const int& newSocketFD, const string& message, const unsigned int& bufferSize);

bool ReceiveMessageSendACK(const int& newSocketFD, string& message, const unsigned int& bufferSize);

bool ReadSocket(const int& newSocketFD, string& message, const unsigned int& bufferSize);

bool WriteSocket(const int& newSocketFD, const string& message, const unsigned int& bufferSize);

bool IsSubdirectory(const string& path, const string& name);

bool IsDirectory(const string& path);

virus *RegisterVirus(const string& virusName, const unsigned int& bloomSize, list& viruses);

string CreateAttribute(string& line, const char& delimiter = ' ');

tm CreateDate(string& line);

void PrintDate(const tm& date);

void ReceiveCommands(const unsigned int& numMonitors, const unsigned int& bufferSize, const unsigned int& sizeOfBloom, const string& inputDir, list& monitors, list& viruses);

void PrintProperUse();

unsigned int CountArguments(const string& command);

void TravelRequest(const unsigned int& bufferSize, list& monitors, list& viruses, unsigned int& totalRequests, unsigned int& acceptedRequests, const string& citizenID, const string& dateStr, const string& countryFrom, const string& countryTo, const string& virusName);

void TravelStats(const unsigned int& bufferSize, list& monitors, list& viruses, const string& virusName, string& dateStr1, string& dateStr2, const string& countryTo = "NOT A COUNTRY");

void AddVaccinationRecords(const unsigned int& bufferSize, const unsigned int& sizeOfBloom, list& monitors, list& viruses, const string& countryFrom);

void SearchVaccinationStatus(const unsigned int& numMonitors, const unsigned int& bufferSize, list& monitors, list& viruses, const string& citizenID);

void Exit(const unsigned int& numMonitors, const unsigned int& bufferSize, list& monitors, const unsigned int& totalRequests, const unsigned int& acceptedRequests);

int main (int argc, char** argv) {
	unsigned int numMonitors;
	unsigned int socketBufferSize;
	unsigned int cyclicBufferSize;
	unsigned int sizeOfBloom;
	string inputDir;
	unsigned int numThreads;
	if (Configure(argc, argv, numMonitors, socketBufferSize, cyclicBufferSize, sizeOfBloom, inputDir, numThreads) == ERROR) {
		PrintProperExec();
		return ERROR;
	}
	if (numMonitors <= 0) {
		cout << "Number of monitors must be a positive integer\n";
		return ERROR;
	}
	if (socketBufferSize < MINIMUM_SOCKET_BUFFER_SIZE) {
		cout << "Socket buffer size is too small\n";
		return ERROR;
	}
	if (cyclicBufferSize < MINIMUM_CYCLIC_BUFFER_SIZE) {
		cout << "Cyclic buffer size is too small\n";
		return ERROR;
	}
	if (numThreads <= 0) {
		cout << "Number of threads must be a positive integer\n";
		return ERROR;
	}
	list monitors;
	if (CreateSockets(numMonitors, monitors) == ERROR) {
		cout << "Error occured during the creation of sockets\n";
		DeleteSockets(numMonitors, monitors);
		return ERROR;
	}
	if (RoundRobin(numMonitors, inputDir, monitors) == ERROR) {  /* Perform round robin to distribute countries */
		cout << "Error occured during round robin\n";
		DeleteSockets(numMonitors, monitors);
		return ERROR;
	}
	if (CreateMonitors(numMonitors, socketBufferSize, cyclicBufferSize, sizeOfBloom, inputDir, numThreads, monitors) == ERROR) {
		cout << "Error occured during the creation of monitors\n";
		while(wait(NULL) > 0);
		DeleteSockets(numMonitors, monitors);
		return ERROR;
	}
	if (AcceptConnections(numMonitors, monitors) == ERROR) {
		cout << "Error occured during the establishment of connections\n";
		while(wait(NULL) > 0);
		DeleteSockets(numMonitors, monitors);
		return ERROR;
	}
	list viruses;
	if (ReceiveBloomFilters(numMonitors, socketBufferSize, sizeOfBloom, monitors, viruses) == ERROR) {
		cout << "Error occured during the reception of bloom filters\n";
		while(wait(NULL) > 0);
		DeleteSockets(numMonitors, monitors);
		return ERROR;
	}
	
	ReceiveCommands(numMonitors, socketBufferSize, sizeOfBloom, inputDir, monitors, viruses);
	
	CloseConnections(numMonitors, monitors);
	while(wait(NULL) > 0);
	DeleteSockets(numMonitors, monitors);
	return OK;
}

bool Configure(const int& argc, char** argv, unsigned int& numMonitors, unsigned int& socketBufferSize, unsigned int& cyclicBufferSize, unsigned int& sizeOfBloom, string& inputDir, unsigned int& numThreads) {
	if (argc == 13) {
		srand(time(NULL));
		for (unsigned i = 1; i < argc; i += 2) {
			if (string(argv[i]) == "-m")
				numMonitors = atoi(argv[i + 1]);
			else if (string(argv[i]) == "-b")
				socketBufferSize = atoi(argv[i + 1]);
			else if (string(argv[i]) == "-c")
				cyclicBufferSize = atoi(argv[i + 1]);
			else if (string(argv[i]) == "-s")
				sizeOfBloom = atoi(argv[i + 1]);
			else if (string(argv[i]) == "-i")
				inputDir = string(argv[i + 1]);
			else if (string(argv[i]) == "-t")
				numThreads = atoi(argv[i + 1]);
			else
				return ERROR;
		}
		return OK;
	}
	return ERROR;
}

void PrintProperExec() {
	cout << "Please try: ./travelMonitorClient -m numMonitors -b socketBufferSize -c cyclicBufferSize -s sizeOfBloom -i input_dir -t numThreads\n";
}

string GetIpAddress() {
	char hostname[MAX_HOSTNAME_LENGTH];
	hostname[MAX_HOSTNAME_LENGTH - 1] = '\0';
	gethostname(hostname, MAX_HOSTNAME_LENGTH - 1);  /* Find current host's name */
	struct hostent *hostEntry;
	hostEntry = gethostbyname(hostname);
	if (hostEntry == NULL) {
		herror("gethostbyname");
		return "";
	}
	struct in_addr **addr_list;
	addr_list = (struct in_addr **) hostEntry->h_addr_list;
	return inet_ntoa(*addr_list[0]);  /* Convert his ip address to string */
}

int GetRandomPort() {
	int portRange = MAX_PORT - MIN_PORT;
	return MIN_PORT + (rand() % ++portRange);
}

int BindOnPort(const int& socketFD, const string& IP, const int& port) {
	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(IP.c_str());
	server.sin_port = htons(port);
	return bind(socketFD, (struct sockaddr *) &server, sizeof(server));
}

bool CreateSockets(const unsigned int& numMonitors, list& monitors) {
	string IP = GetIpAddress();
	for (unsigned int i = 1; i <= numMonitors; i++) {
		int socketFD = socket(AF_INET, SOCK_STREAM, 0);
		if (socketFD == - 1) {
			perror("socket");
			return ERROR;
		}
		int port = GetRandomPort();
		while (BindOnPort(socketFD, IP, port) < 0)  /* Find available port */
			port = GetRandomPort();
		if (listen(socketFD, 1) == -1) {  /* Listen for connection requests */
			perror("listen");
			return ERROR;
		}
		monitor mntrTemp(i, socketFD, port);  /* Store info about monitor */
		monitors.Insert(mntrTemp);  /* Add to the list */
	}
	return OK;
}

void DeleteSockets(const unsigned int& numMonitors, list& monitors) {
	for (unsigned int i = 1; i <= numMonitors; i++) {
		monitor mntrTemp(i);
		nodeData *dataPtr = monitors.Search(mntrTemp);
		if (dataPtr != NULL) {
			monitor *mntrPtr = dynamic_cast<monitor *>(dataPtr);
			int socketFD = mntrPtr->GetSocketFD();
			close(socketFD);  /* Delete socket */
		}
	}
}

bool AcceptConnections(const unsigned int& numMonitors, list& monitors) {
	for (unsigned int i = 1; i <= numMonitors; i++) {
		monitor mntrTemp(i);
		nodeData *dataPtr = monitors.Search(mntrTemp);
		if (dataPtr == NULL)
			return ERROR;
		monitor *mntrPtr = dynamic_cast<monitor *>(dataPtr);
		int socketFD = mntrPtr->GetSocketFD();
		
		int newSocketFD = accept(socketFD, NULL, NULL);  /* Accept connection request */
		if (newSocketFD < 0) {
			perror("accept");
			return ERROR;
		}
		
		int optValue = 1;
		if (setsockopt(newSocketFD, IPPROTO_TCP, TCP_NODELAY, &optValue, sizeof(optValue)) < 0) {  /* Set no delay option for TCP socket */
			perror("setsockopt");
			return ERROR;
		}
		mntrPtr->SetNewSocketFD(newSocketFD);
	}
	return OK;
}

void CloseConnections(const unsigned int& numMonitors, list& monitors) {
	for (unsigned int i = 1; i <= numMonitors; i++) {
		monitor mntrTemp(i);
		nodeData *dataPtr = monitors.Search(mntrTemp);
		if (dataPtr != NULL) {
			monitor *mntrPtr = dynamic_cast<monitor *>(dataPtr);
			int newSocketFD = mntrPtr->GetNewSocketFD();
			close(newSocketFD);  /* Close connection */
		}
	}
}

bool RoundRobin(const unsigned int& numMonitors, const string& inputDir, list& monitors) {
	string path = "./" + inputDir;
	struct dirent **entries;
	int numOfEntries = scandir(path.c_str(), &entries, NULL, alphasort);  /* Get the entries of inputDir in alphabetical order */
	if (numOfEntries < 0)
		return ERROR;
	unsigned int i = 1;
	for(unsigned int j = 0; j < numOfEntries; j++ ) {
		string countryName = entries[j]->d_name;
		string newPath = path + "/" + countryName;
		if (IsSubdirectory(newPath, countryName)) {  /* If it is actually a subdirectory */
			monitor mntrTemp(i);
			nodeData *dataPtr = monitors.Search(mntrTemp);
			if (dataPtr == NULL)
				return ERROR;
			monitor *mntrPtr = dynamic_cast<monitor *>(dataPtr);
			mntrPtr->AddCountry(countryName);  /* Update the info about this monitor */
			if (++i > numMonitors)  /* Find next monitor */
				i = 1;  /* If it exceeds numMonitors, start all over again (Round Robin) */
		}
		free(entries[j]);  /* Free memory allocated by scandir */
	}
	free(entries);  /* Free memory allocated by scandir */
	return OK;
}

bool CreateMonitors(const unsigned int& numMonitors, const unsigned int& socketBufferSize, const unsigned int& cyclicBufferSize, const unsigned int& sizeOfBloom, const string& inputDir, const unsigned int& numThreads, list& monitors) {
	cout << "Loading records...\n";
	pid_t childpid;
	for (unsigned int i = 1; i <= numMonitors; i++) {
		monitor mntrTemp(i);
		nodeData *dataPtr = monitors.Search(mntrTemp);
		if (dataPtr == NULL)
			return ERROR;
		monitor *mntrPtr = dynamic_cast<monitor *>(dataPtr);
		childpid = fork();
		if (childpid < 0) {  /* Error */
			perror("fork");
			return ERROR;
		}
		else if (childpid == 0) {  /* Child process */
			int argc = 11 + mntrPtr->GetCountries().GetNodeCount();
			char **argv = new char *[argc + 1];
			argv[argc] = NULL;
			
			argv[0] = new char[strlen("./monitorServer") + 1];
			strcpy(argv[0], "./monitorServer");
			
			argv[1] = new char[strlen("-p") + 1];
			strcpy(argv[1], "-p");
			
			int port = mntrPtr->GetPort();
			argv[2] = new char[strlen(to_string(port).c_str()) + 1];
			strcpy(argv[2], to_string(port).c_str());
			
			argv[3] = new char[strlen("-t") + 1];
			strcpy(argv[3], "-t");
			
			argv[4] = new char[strlen(to_string(numThreads).c_str()) + 1];
			strcpy(argv[4], to_string(numThreads).c_str());
			
			argv[5] = new char[strlen("-b") + 1];
			strcpy(argv[5], "-b");
			
			argv[6] = new char[strlen(to_string(socketBufferSize).c_str()) + 1];
			strcpy(argv[6], to_string(socketBufferSize).c_str());
			
			argv[7] = new char[strlen("-c") + 1];
			strcpy(argv[7], "-c");
			
			argv[8] = new char[strlen(to_string(cyclicBufferSize).c_str()) + 1];
			strcpy(argv[8], to_string(cyclicBufferSize).c_str());
			
			argv[9] = new char[strlen("-s") + 1];
			strcpy(argv[9], "-s");
			
			argv[10] = new char[strlen(to_string(sizeOfBloom).c_str()) + 1];
			strcpy(argv[10], to_string(sizeOfBloom).c_str());
			
			unsigned int argcPaths = 11;
			const listNode *node = mntrPtr->GetCountries().GetHead();
			while (node != NULL) {  /* Let the monitor know for which countries it's responsible */
				const nodeData *dataPtr = node->GetData();
				const country *cntrPtr = dynamic_cast<const country *>(dataPtr);
				if (cntrPtr != NULL) {
					string countryName = cntrPtr->GetName();
					string path = "./" + inputDir + "/" + countryName;
					argv[argcPaths] = new char[strlen(path.c_str()) + 1];
					strcpy(argv[argcPaths], path.c_str());
					argcPaths++;
				}
				node = node->GetNext();
			}
			execv(argv[0], argv);
			perror("execv");  /* This point shouldn't be reached */
			for (unsigned int i = 0; i < argc; i++)  /* If exec didn't happen, free argv manually */
				delete argv[i];
			delete[] argv;
			return ERROR;
		}
		else  /* Parent process */			
			mntrPtr->SetPID(childpid);  /* Save monitor's pid */
	}
	return OK;
}

bool ReceiveBloomFilters(const unsigned int& numMonitors, const unsigned int& bufferSize, const unsigned int& sizeOfBloom, list& monitors, list& viruses) {
	string message;
	
	for (unsigned int i = 1; i <= numMonitors; i++) {  /* For each monitor */
		monitor mntrTemp(i);
		nodeData *dataPtr = monitors.Search(mntrTemp);
		if (dataPtr == NULL)
			return ERROR;
		monitor *mntrPtr = dynamic_cast<monitor *>(dataPtr);
		int newSocketFD = mntrPtr->GetNewSocketFD();  /* Get file descriptor for socket */
		
		while (1) {  /* Receive bloom filters of every virus this monitor has available */
			if (ReceiveMessageSendACK(newSocketFD, message, bufferSize) == ERROR)  /* Receive virusName */
				return ERROR;
			if (message == STOP) {
				break;
			}
			string virusName = message;
			virus *vrsPtr = RegisterVirus(virusName, sizeOfBloom, viruses);
			
			if (ReceiveMessageSendACK(newSocketFD, message, bufferSize) == ERROR)  /* Receive bitArray of its bloom */
				return ERROR;
			string bitArray = message;
			bloomFilter bloom(sizeOfBloom);  /* Create a temporary bloom with same size */
			bloom.SetBitArray(bitArray.c_str());  /* Set bitArray as the received one */
			vrsPtr->UpdateBloom(bloom);  /* Update the existing bloom of this virus */
		}
	}
	
	return OK;
}

bool SendMessageReceiveACK(const int& newSocketFD, const string& message, const unsigned int& bufferSize) {
	if (WriteSocket(newSocketFD, message, bufferSize) == ERROR) {  /* Write message to socket */
		cout << "Cannot write to socket " << newSocketFD << "\n";
		return ERROR;
	}
	if (message == STOP)  /* In case of STOP, there won't be an acknowledgment */
		return OK;
	string response;
	if (ReadSocket(newSocketFD, response, bufferSize) == ERROR) {  /* Read acknowledgment from socket */
		cout << "Cannot read from socket " << newSocketFD << "\n";
		return ERROR;
	}
	if (response != ACK) {
		cout << "Didn't receive acknowledgment\n";
		return ERROR;
	}
	return OK;
}

bool ReceiveMessageSendACK(const int& newSocketFD, string& message, const unsigned int& bufferSize) {
	if (ReadSocket(newSocketFD, message, bufferSize) == ERROR) {  /* Read message from socket */
		cout << "Cannot read from socket " << newSocketFD << "\n";
		return ERROR;
	}
	if (message == STOP)  /* In case of STOP, don't send acknowledgment */
		return OK;
	string response = ACK;
	if (WriteSocket(newSocketFD, response, bufferSize) == ERROR) {  /* Write acknowledgment to socket */
		cout << "Cannot write to socket " << newSocketFD << "\n";
		return ERROR;
	}
	return OK;
}

bool ReadSocket(const int& newSocketFD, string& message, const unsigned int& bufferSize) {
	message = "";
	string messageEnd = END_OF_MESSAGE;
	char *buffer = new char[bufferSize];
	int bytes;
	while (bytes = read(newSocketFD, buffer, bufferSize)) {  /* Read at most bufferSize bytes */
		if (bytes < 0) {
			perror("read");
			delete[] buffer;
			return ERROR;
		}
		if (buffer[bytes - 1] == messageEnd[0]) {  /* End of message is not actual content */
			message += string(buffer, bytes - 1);  /* Append buffer to message */
			break;
		}
		message += string(buffer, bytes);  /* Append buffer to message */
	}
	delete[] buffer;
	return OK;
}

bool WriteSocket(const int& newSocketFD, const string& message, const unsigned int& bufferSize) {	
	char *buffer = new char[bufferSize];
	for (unsigned int send = 0; send < message.length();) {  /* Send message through buffer */
		unsigned int size = bufferSize;
		if (send + bufferSize > message.length())
			size = message.length() - send;
		memcpy(buffer, message.substr(send, size).c_str(), size);
		if (write(newSocketFD, buffer, size) != size) {  /* Write size bytes at each time */
			perror("write");
			delete[] buffer;
			return ERROR;
		}
		send += size;  /* Sent bytes so far */
	}
	string messageEnd = END_OF_MESSAGE;
	memcpy(buffer, messageEnd.c_str(), messageEnd.length());
	write(newSocketFD, buffer, messageEnd.length());  /* Write end of message */
	delete[] buffer;
	return OK;
}

bool IsSubdirectory(const string& path, const string& name) {
	if (name != "." && name != "..")
		return IsDirectory(path);
	return 0;
}

bool IsDirectory(const string& path) {
	struct stat statBuf;
	if (stat(path.c_str(), &statBuf))
		return 0;
	return S_ISDIR(statBuf.st_mode);
}

virus *RegisterVirus(const string& virusName, const unsigned int& bloomSize, list& viruses) {
	virus vrsTemp(virusName, bloomSize);
	nodeData *dataPtr = viruses.Search(vrsTemp);
	if (dataPtr == NULL) {
		viruses.Insert(vrsTemp);
		dataPtr = viruses.Search(vrsTemp);
	}
	virus *vrsPtr = dynamic_cast<virus *>(dataPtr);
	return vrsPtr;
}

string CreateAttribute(string& line, const char& delimiter) {  /* Extract substring before delimiter */
	unsigned int attrLength = line.find_first_of(delimiter);
	string attribute = line.substr(0, attrLength);
	if (line.length() > attrLength)
		line = line.substr(attrLength + 1);
	else
		line = "";
	return attribute;
}

tm CreateDate(string& line) {
	tm date = {0};
	date.tm_mday = atoi(CreateAttribute(line, '-').c_str());
	date.tm_mon = atoi(CreateAttribute(line, '-').c_str()) - 1;
	date.tm_year = atoi(CreateAttribute(line, '-').c_str()) - 1900;
	return date;
}

void PrintDate(const tm& date) {
	cout << date.tm_mday << "-" << 1 + date.tm_mon << "-" << 1900 + date.tm_year;
}

void ReceiveCommands(const unsigned int& numMonitors, const unsigned int& bufferSize, const unsigned int& sizeOfBloom, const string& inputDir, list& monitors, list& viruses) {
	unsigned int totalRequests = 0;
	unsigned int acceptedRequests = 0;
	cout << "Give any command:\n";
	string command;
	while (getline(cin, command)) {
		unsigned int argCount = CountArguments(command);
		istringstream sstream(command);
		string function, argument1, argument2, argument3, argument4, argument5;
		sstream >> function >> argument1 >> argument2 >> argument3 >> argument4 >> argument5;
		if (function == "/travelRequest") {
			if (argCount == 5) {
				TravelRequest(bufferSize, monitors, viruses, totalRequests, acceptedRequests, argument1, argument2, argument3, argument4, argument5);
			}
			else
				PrintProperUse();
		}
		else if (function == "/travelStats") {
			if (argCount == 3)
				TravelStats(bufferSize, monitors, viruses, argument1, argument2, argument3);
			else if (argCount == 4)
				TravelStats(bufferSize, monitors, viruses, argument1, argument2, argument3, argument4);
			else
				PrintProperUse();
		}
		else if (function == "/addVaccinationRecords") {
			if (argCount == 1)
				AddVaccinationRecords(bufferSize, sizeOfBloom, monitors, viruses, argument1);
			else
				PrintProperUse();
		}
		else if (function == "/searchVaccinationStatus") {
			if (argCount == 1)
				SearchVaccinationStatus(numMonitors, bufferSize, monitors, viruses, argument1);
			else
				PrintProperUse();
		}
		else if (function == "/exit") {
			if (argCount == 0) {
				Exit(numMonitors, bufferSize, monitors, totalRequests, acceptedRequests);
				return;
			}
			else
				PrintProperUse();
		}
		else
			PrintProperUse();
	}
}

void PrintProperUse() {
	cout << "Please try one of the following:\n"
				<< "/travelRequest citizenID date countryFrom countryTo virusName\n"
				<< "/travelStats virusName date1 date2 [country]\n"
				<< "/addVaccinationRecords country\n"
				<< "/searchVaccinationStatus citizenID\n"
				<< "/exit\n";
}

unsigned int CountArguments(const string& command) {
	istringstream sstream(command);
	string function, argument;
	sstream >> function;
	unsigned int count = 0;
	do {
		argument = "";
		sstream >> argument;
		if (!argument.empty())
			count++;
	} while(!argument.empty());
	return count;
}

void TravelRequest(const unsigned int& bufferSize, list& monitors, list& viruses, unsigned int& totalRequests, unsigned int& acceptedRequests, const string& citizenID, const string& dateStr, const string& countryFrom, const string& countryTo, const string& virusName) {
	int monitorID;
	const country *cntrPtr;
	const listNode *node = monitors.GetHead();
	unsigned int count = 0;
	while (node != NULL) {  /* Find which monitor is responsible for countryFrom */
		const nodeData *dataPtr = node->GetData();
		const monitor *mntrPtr = dynamic_cast<const monitor *>(dataPtr);
		cntrPtr = mntrPtr->GetCountry(countryFrom);
		if (cntrPtr != NULL) {
			monitorID = mntrPtr->GetMonitorID();
			count++;
			break;
		}
		node = node->GetNext();
	}
	if (count == 0) {  /* Not registered countryFrom */
		cout << "ERROR: " << countryFrom << " IS NOT A VALID COUNTRY\n";
		return;
	}
	node = monitors.GetHead();
	count = 0;
	while (node != NULL) {  /* Check if there is a monitor responsible for countryTo */
		const nodeData *dataPtr = node->GetData();
		const monitor *mntrPtr = dynamic_cast<const monitor *>(dataPtr);
		cntrPtr = mntrPtr->GetCountry(countryTo);
		if (cntrPtr != NULL) {
			count++;
			break;
		}
		node = node->GetNext();
	}
	if (count == 0) {  /* Not registered countryTo */
		cout << "ERROR: " << countryTo << " IS NOT A VALID COUNTRY\n";
		return;
	}
	virus vrsTemp(virusName, 0);
	nodeData *dataPtr = viruses.Search(vrsTemp);
	if (dataPtr == NULL) {  /* Not registered virus */
		cout << "ERROR: " << virusName << " IS NOT A VALID VIRUS\n";
		return;
	}
	totalRequests++;  /* Increase total requests */
	string travelDateStr = dateStr;
	tm travelDate = CreateDate(travelDateStr);
	virus *vrsPtr = dynamic_cast<virus *>(dataPtr);
	if (vrsPtr->SearchBloom(citizenID)) {  /* If virus' bloom says that it's possible for citizen to be vaccinated */
		monitor mntrTemp(monitorID);
		nodeData *dataPtr = monitors.Search(mntrTemp);
		if (dataPtr == NULL)
			return;
		monitor *mntrPtr = dynamic_cast<monitor *>(dataPtr);
		int newSocketFD = mntrPtr->GetNewSocketFD();  /* Get file descriptor for socket */
		string message = "/travelRequest " + citizenID + " " + dateStr + " " + countryFrom + " " + virusName;
		if (SendMessageReceiveACK(newSocketFD, message, bufferSize) == ERROR)  /* Send command and citizenID, date, countryFrom, virus */
			return;
		message = STOP;
		if (SendMessageReceiveACK(newSocketFD, message, bufferSize) == ERROR)
			return;
		if (ReceiveMessageSendACK(newSocketFD, message, bufferSize) == ERROR)  /* Receive vaccinated status */
			return;
		string vaccinated = CreateAttribute(message);
		if (vaccinated == "YES") {  /* If citizen has been vaccinated, check the vaccine date to determine if he's eligible to travel */
			tm vaccineDate = CreateDate(message);
			double difSeconds = difftime(mktime(&travelDate), mktime(&vaccineDate));  /* Compare travel date to vaccine date */
			if (difSeconds >= 0 && difSeconds / 60 / 60 / 24 / 30 < 6) {  /* Difference in seconds -> minutes -> hours -> days -> months */
				cout << "REQUEST ACCEPTED - HAPPY TRAVELS\n";  /* Accept request if difference is less than 6 months (180 days) */
				travelRequest tRequestTemp(travelDate, ACCEPTED);
				vrsPtr->AddTravelRequest(tRequestTemp, *cntrPtr);  /* Store travel request */
				acceptedRequests++;  /* Increase accepted requests */
				if (ReceiveMessageSendACK(newSocketFD, message, bufferSize) == ERROR)
					return;
				if (message != STOP)
					return;
				return;
			}
			else {  /* If the difference is greater than 6 months or the travel date is before the vaccine date */
				cout << "REQUEST REJECTED - YOU WILL NEED ANOTHER VACCINATION BEFORE TRAVEL DATE\n";  /* He has to get vaccinated before travel date */
				travelRequest tRequestTemp(travelDate, REJECTED);
				vrsPtr->AddTravelRequest(tRequestTemp, *cntrPtr);  /* Store travel request */
			}
		}
		else if (vaccinated == "NO") {  /* If citizen hasn't been vaccinated, reject his request */
			cout << "REQUEST REJECTED - YOU ARE NOT VACCINATED\n";
			travelRequest tRequestTemp(travelDate, REJECTED);
			vrsPtr->AddTravelRequest(tRequestTemp, *cntrPtr);  /* Store travel request */
		}
		if (ReceiveMessageSendACK(newSocketFD, message, bufferSize) == ERROR)
			return;
		if (message != STOP)
			return;
	}
	else {  /* If virus' bloom has negative answer, citizen is definitely not vaccinated and his request is rejected */
		cout << "REQUEST REJECTED - YOU ARE NOT VACCINATED\n";
		travelRequest tRequestTemp(travelDate, REJECTED);
		vrsPtr->AddTravelRequest(tRequestTemp, *cntrPtr);  /* Store travel request */
	}
}

void TravelStats(const unsigned int& bufferSize, list& monitors, list& viruses, const string& virusName, string& dateStr1, string& dateStr2, const string& countryTo) {
	virus vrsTemp(virusName, 0);
	nodeData *dataPtr = viruses.Search(vrsTemp);
	if (dataPtr == NULL) {  /* Not registered virus */
		cout << "ERROR: " << virusName << " IS NOT A VALID VIRUS\n";
		return;
	}
	if (countryTo != "NOT A COUNTRY") {
		const listNode *node = monitors.GetHead();
		unsigned int count = 0;
		while (node != NULL) {  /* Check if there is a monitor responsible for countryTo */
			const nodeData *dataPointer = node->GetData();
			const monitor *mntrPtr = dynamic_cast<const monitor *>(dataPointer);
			const country *cntrPtr = mntrPtr->GetCountry(countryTo);
			if (cntrPtr != NULL) {
				count++;
				break;
			}
			node = node->GetNext();
		}
		if (count == 0) {  /* Not registered countryTo */
			cout << "ERROR: " << countryTo << " IS NOT A VALID COUNTRY\n";
			return;
		}
	}
	virus *vrsPtr = dynamic_cast<virus *>(dataPtr);
	tm date1 = CreateDate(dateStr1);
	tm date2 = CreateDate(dateStr2);
	vrsPtr->PrintTravelStats(date1, date2, countryTo);  /* Print virus' stats based on travel requests between date1 and date2 */
}

void AddVaccinationRecords(const unsigned int& bufferSize, const unsigned int& sizeOfBloom, list& monitors, list& viruses, const string& countryFrom) {
	int monitorID;
	int newSocketFD;
	const country *cntrPtr;
	const listNode *node = monitors.GetHead();
	unsigned int count = 0;
	while (node != NULL) {  /* Find which monitor is responsible for countryFrom */
		const nodeData *dataPtr = node->GetData();
		const monitor *mntrPtr = dynamic_cast<const monitor *>(dataPtr);
		cntrPtr = mntrPtr->GetCountry(countryFrom);
		if (cntrPtr != NULL) {
			monitorID = mntrPtr->GetMonitorID();
			newSocketFD = mntrPtr->GetNewSocketFD();  /* Get file descriptor for socket */
			count++;
			break;
		}
		node = node->GetNext();
	}
	if (count == 0) {  /* Not registered countryFrom */
		cout << "ERROR: " << countryFrom << " IS NOT A VALID COUNTRY\n";
		return;
	}
	
	string message = "/addVaccinationRecords " + countryFrom;
	if (SendMessageReceiveACK(newSocketFD, message, bufferSize) == ERROR)  /* Send command and countryFrom */
		return;
	message = STOP;
	if (SendMessageReceiveACK(newSocketFD, message, bufferSize) == ERROR)
		return;
	
	while (1) {  /* Receive new bloom filters of every virus this monitor has available */
		if (ReceiveMessageSendACK(newSocketFD, message, bufferSize) == ERROR)  /* Receive virusName */
			return;
		if (message == STOP) {
			break;
		}
		string virusName = message;
		virus *vrsPtr = RegisterVirus(virusName, sizeOfBloom, viruses);
		
		if (ReceiveMessageSendACK(newSocketFD, message, bufferSize) == ERROR)  /* Receive bitArray of its bloom */
			return;
		string bitArray = message;
		bloomFilter bloom(sizeOfBloom);  /* Create a temporary bloom with same size */
		bloom.SetBitArray(bitArray.c_str());  /* Set bitArray as the received one */
		vrsPtr->UpdateBloom(bloom);  /* Update the existing bloom of this virus */
	}
	cout << "DONE\n";
}

void SearchVaccinationStatus(const unsigned int& numMonitors, const unsigned int& bufferSize, list& monitors, list& viruses, const string& citizenID) {
	int count = 0;
	for (unsigned int i = 1; i <= numMonitors; i++) { /* To every monitor */
		monitor mntrTemp(i);
		nodeData *dataPtr = monitors.Search(mntrTemp);
		if (dataPtr == NULL)
			return;
		monitor *mntrPtr = dynamic_cast<monitor *>(dataPtr);
		int newSocketFD = mntrPtr->GetNewSocketFD();  /* Get file descriptor for socket */
		string message = "/searchVaccinationStatus " + citizenID;
		if (SendMessageReceiveACK(newSocketFD, message, bufferSize) == ERROR)  /* Send citizenID */
			return;
		message = STOP;
		if (SendMessageReceiveACK(newSocketFD, message, bufferSize) == ERROR)
			return;
		while (1) {
			if (ReceiveMessageSendACK(newSocketFD, message, bufferSize) == ERROR)  /* Receive info about this citizen */
				return;
			if (message == STOP)  /* If message was just a STOP, the current monitor doesn't know anything about him */
				break;
			count++;
			cout << message << "\n";  /* Print info */
		}
	}
	if (count == 0) {  /* Not registered countryFrom */
		cout << "ERROR: CITIZEN " << citizenID << " NOT FOUND AT ANY COUNTRY\n";
		return;
	}
}

void Exit(const unsigned int& numMonitors, const unsigned int& bufferSize, list& monitors, const unsigned int& totalRequests, const unsigned int& acceptedRequests) {
	string filename = "log_file." + to_string(getpid());
	ofstream file(filename);
	
	for (unsigned int i = 1; i <= numMonitors; i++) {  /* For each monitor */
		monitor mntrTemp(i);
		const nodeData *dataPtr = monitors.Search(mntrTemp);
		if (dataPtr == NULL)
			return;
		const monitor *mntrPtr = dynamic_cast<const monitor *>(dataPtr);
		int newSocketFD = mntrPtr->GetNewSocketFD();  /* Get file descriptor for socket */
		string message = "/exit";
		if (SendMessageReceiveACK(newSocketFD, message, bufferSize) == ERROR)  /* Send command */
			return;
		message = STOP;
		if (SendMessageReceiveACK(newSocketFD, message, bufferSize) == ERROR)
			return;
		if (ReceiveMessageSendACK(newSocketFD, message, bufferSize) == ERROR)
			return;
		if (message != "DONE")
			return;
		if (ReceiveMessageSendACK(newSocketFD, message, bufferSize) == ERROR)
			return;
		if (message != STOP)
			return;
		
		pid_t pid = mntrPtr->GetPID();
		waitpid(pid, NULL, 0);  /* Wait monitor process to terminate */
		const listNode *cntrNode = mntrPtr->GetCountries().GetHead();
		while (cntrNode != NULL) {  /* Write all countries that monitor is aware of */
			dataPtr = cntrNode->GetData();
			const country *cntrPtr = dynamic_cast<const country *>(dataPtr);
			file << cntrPtr->GetName() << "\n";
			cntrNode = cntrNode->GetNext();
		}
	}
	
	file << "TOTAL TRAVEL REQUESTS " << totalRequests << "\n";
	file << "ACCEPTED " << acceptedRequests << "\n";
	file << "REJECTED " << (totalRequests - acceptedRequests) << "\n";
	file.close();
}
