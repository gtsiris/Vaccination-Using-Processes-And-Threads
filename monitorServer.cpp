#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include "class_Citizen.h"
#include "class_Country.h"
#include "class_Virus.h"
#include "struct_List.h"
#include "struct_Hash_Table.h"

#define END_OF_MESSAGE "#"  /* Let receiver know that message has been completed */
#define ACK "@"  /* Follow up each message with acknowledgement */
#define STOP "$"  /* Doesn't require ACK. Signifies change of direction in communication */
#define OK 0
#define ERROR !OK
#define DEFAULT_BUCKET_COUNT 1000  /* Rule of thumb: logN, where N is the expected number of records */
#define MAX_HOSTNAME_LENGTH 1024
#define perror2(s, e) fprintf(stderr, "%s: %s\n", s, strerror(e))

using namespace std;

typedef struct {
	string *data;
	int start;
	int end;
	int count;
	int size;
} pool_t;

unsigned int sizeOfBloom;
string inputDir = "";
hashTable citizens(DEFAULT_BUCKET_COUNT);
list countries;
list viruses;
bool more_items = 1;
pthread_mutex_t mtx;
pthread_cond_t cond_nonempty;
pthread_cond_t cond_nonfull;
pool_t pool;

void initialize(pool_t *pool, int pool_size);

void destroy(pool_t *pool);

void place(pool_t *pool, string data);

string obtain(pool_t *pool);

void *consumer(void *ptr);

bool Configure(const int& argc, char **argv, int& port, unsigned int& numThreads, unsigned int& socketBufferSize, unsigned int& cyclicBufferSize, unsigned int& sizeOfBloom, string& inputDir, list& oldCountryFiles, pthread_t *consumers);

bool CreateThreads(pthread_t *consumers, const unsigned int& numThreads, const unsigned int& cyclicBufferSize);

void DeleteThreads(pthread_t *consumers, const unsigned int& numThreads);

void PrintProperExec();

string GetIpAddress();

int ConnectToSocket(const int& socketFD, const string& IP, const int& port);

bool CreateSocket(int& socketFD, const int& port);

void DeleteSocket(const int& socketFD);

bool SendBloomFilters(const int& socketFD, const unsigned int& bufferSize, const unsigned int& sizeOfBloom, list& viruses);

bool SendMessageReceiveACK(const int& socketFD, const string& message, const unsigned int& bufferSize);

bool ReceiveMessageSendACK(const int& socketFD, string& message, const unsigned int& bufferSize);

bool ReadSocket(const int& socketFD, string& message, const unsigned int& bufferSize);

bool WriteSocket(const int& socketFD, const string& message, const unsigned int& bufferSize);

string BitArrayToString(const char *bitArray, const unsigned int& size);

bool IsRegularFile(const string& path);

bool ProduceFromDirectory(const string& path, list& oldCountryFiles);

bool InputFromFile(const string& path, hashTable& citizens, list& countries, list& viruses, const unsigned int& bloomSize);

bool InputFromLine(string line, hashTable& citizens, list& countries, list& viruses, const unsigned int& bloomSize);

country *RegisterCountry(const string& countryName, list& countries);

citizen *RegisterCitizen(const string& citizenID, const string& firstName, const string& lastName, const country& cntr, const unsigned int& age, hashTable& citizens);

virus *RegisterVirus(const string& virusName, const unsigned int& bloomSize, list& viruses);

string CreateAttribute(string& line, const char& delimiter = ' ');

tm CreateDate(string& line);

string DateToString(const tm& date);

void PrintDate(const tm& date);

void ReceiveCommands(const int& socketFD, const unsigned int& bufferSize, const unsigned int& sizeOfBloom, const string& inputDir, hashTable& citizens, list& countries, list& viruses, list& oldCountryFiles);

void PrintProperUse();

unsigned int CountArguments(const string& command);

void TravelRequest(const int& socketFD, const unsigned int& bufferSize, hashTable& citizens, list& viruses, unsigned int& totalRequests, unsigned int& acceptedRequests, const string& citizenID, const string& dateStr, const string& countryFrom, const string& virusName);

void AddVaccinationRecords(const int& socketFD, const unsigned int& bufferSize, const unsigned int& sizeOfBloom, const string& inputDir, list& countries, list& viruses, list& oldCountryFiles, const string& countryFrom);

void SearchVaccinationStatus(const int& socketFD, const unsigned int& bufferSize, hashTable& citizens, list& viruses, const string& citizenID);

void Exit(const int& socketFD, const unsigned int& bufferSize, list& countries, const unsigned int& totalRequests, const unsigned int& acceptedRequests);

void CreateLogFile(list& countries, const unsigned int& totalRequests, const unsigned int& acceptedRequests);

int main (int argc, char** argv) {
	int port;
	unsigned int numThreads;
	unsigned int socketBufferSize;
	unsigned int cyclicBufferSize;
	list oldCountryFiles;  /* List of the already processed country files */
	pthread_t *consumers = NULL;
	if (Configure(argc, argv, port, numThreads, socketBufferSize, cyclicBufferSize, sizeOfBloom, inputDir, oldCountryFiles, consumers) == ERROR) {  /* Includes creation of threads */
		PrintProperExec();
		DeleteThreads(consumers, numThreads);
		return ERROR;
	}
	int socketFD;
	if (CreateSocket(socketFD, port) == ERROR) {
		cout << "Monitor failed to create socket\n";
		DeleteSocket(socketFD);
		DeleteThreads(consumers, numThreads);
		return ERROR;
	}
	if (SendBloomFilters(socketFD, socketBufferSize, sizeOfBloom, viruses) == ERROR) {
		cout << "Monitor failed to send bloom filters\n";
		DeleteSocket(socketFD);
		DeleteThreads(consumers, numThreads);
		return ERROR;
	}
	
	ReceiveCommands(socketFD, socketBufferSize, sizeOfBloom, inputDir, citizens, countries, viruses, oldCountryFiles);
	
	DeleteSocket(socketFD);
	DeleteThreads(consumers, numThreads);
	return OK;
}

void initialize(pool_t *pool, int pool_size) {
	pool->data = new string[pool_size];
	pool->start = 0;
	pool->end = -1;
	pool->count = 0;
	pool->size = pool_size;
}

void destroy(pool_t *pool) {
	delete[] pool->data;
}

void place(pool_t *pool, string data) {
	pthread_mutex_lock(&mtx);
	while (pool->count >= pool->size) {
//		cout << ">> Found Buffer Full\n";
		pthread_cond_wait(&cond_nonfull, &mtx);  /* Wait for available space */
	}
	pool->end = (pool->end + 1) % pool->size;
	pool->data[pool->end] = data;
	pool->count++;
	pthread_mutex_unlock(&mtx);
}

string obtain(pool_t *pool) {
	string data;
	pthread_mutex_lock(&mtx);
	while (pool->count <= 0) {
//		cout << ">> Found Buffer Empty\n";
		pthread_cond_wait(&cond_nonempty, &mtx);  /* Wait for available items */
	}
	data = pool->data[pool->start];
	pool->start = (pool->start + 1) % pool->size;
	pool->count--;
	string countryName = data.substr(0, data.find_last_of('-'));
	string newPath = "./" + inputDir + "/" + countryName + "/" + data;
	if (InputFromFile(newPath, citizens, countries, viruses, sizeOfBloom) == ERROR)  /* Update global structs with file's content */
		cout << "ERROR IN FILE " << data << "\n";
	pthread_mutex_unlock(&mtx);
	return data;
}

void *consumer(void *ptr) {
	while (more_items || pool.count > 0) {  /* Either there are items in cyclic buffer or more incoming items */
		string data = obtain(&pool);
//		cout << "consumer: " << data << "\n";
		pthread_cond_signal(&cond_nonfull);  /* Let producer know there is available space */
	}
	pthread_exit(0);
}

bool Configure(const int& argc, char **argv, int& port, unsigned int& numThreads, unsigned int& socketBufferSize, unsigned int& cyclicBufferSize, unsigned int& sizeOfBloom, string& inputDir, list& oldCountryFiles, pthread_t *consumers) {
	if (argc < 11)
		return ERROR;
	unsigned i = 1;
	for (; i < 11; i += 2) {
		if (string(argv[i]) == "-p")
			port = atoi(argv[i + 1]);
		else if (string(argv[i]) == "-t")
			numThreads = atoi(argv[i + 1]);
		else if (string(argv[i]) == "-b")
			socketBufferSize = atoi(argv[i + 1]);
		else if (string(argv[i]) == "-c")
			cyclicBufferSize = atoi(argv[i + 1]);
		else if (string(argv[i]) == "-s")
			sizeOfBloom = atoi(argv[i + 1]);
		else
			return ERROR;
	}
	if (argv[i] == NULL)
		return OK;
	
	string path = string(argv[i]);
	inputDir = path.substr(2);
	inputDir = inputDir.substr(0, inputDir.find_first_of('/'));  /* Store input directory's name */
	
	if (CreateThreads(consumers, numThreads, cyclicBufferSize) == ERROR)  /* Create threads that operating as consumers */
		return ERROR;
	
	while (argv[i] != NULL) {  /* For each given path */
		string path = string(argv[i]);
		if (ProduceFromDirectory(path, oldCountryFiles) == ERROR)  /* Add files from country's directory to cyclic buffer */
			return ERROR;
		i++;
	}
	
	return OK;
}

bool CreateThreads(pthread_t *consumers, const unsigned int& numThreads, const unsigned int& cyclicBufferSize) {
	consumers = new pthread_t[numThreads];
	
	initialize(&pool, cyclicBufferSize);
	pthread_mutex_init(&mtx, 0);
	pthread_cond_init(&cond_nonempty, 0);
	pthread_cond_init(&cond_nonfull, 0);
	
	for (unsigned int thr = 0; thr < numThreads; thr++) {
		if (int error = pthread_create(&consumers[thr], 0, consumer, 0)) {  /* Create consumer-thread */
			perror2("pthread_create", error);
			return ERROR;
		}
	}
	
	return OK;
}

void DeleteThreads(pthread_t *consumers, const unsigned int& numThreads) {
	more_items = 0;  /* No more incoming items */
	
	for (unsigned int thr = 0; thr < numThreads; thr++) {
		if (int error = pthread_join(consumers[thr], 0)) {  /* Wait consumer-thread to terminate */
			perror2("pthread_join", error);
			return;
		}
	}
	
	pthread_cond_destroy(&cond_nonempty);
	pthread_cond_destroy(&cond_nonfull);
	pthread_mutex_destroy(&mtx);
	destroy(&pool);
	
	delete[] consumers;
}

void PrintProperExec() {
	cout << "To exec monitor please try: ./monitorServer -p port -t numThreads -b socketBufferSize -c cyclicBufferSize -s sizeOfBloom path1 path2 ... pathn\n";
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

int ConnectToSocket(const int& socketFD, const string& IP, const int& port) {
	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(IP.c_str());
	server.sin_port = htons(port);
	return connect(socketFD, (struct sockaddr *) &server, sizeof(server));
}

bool CreateSocket(int& socketFD, const int& port) {
	socketFD = socket(AF_INET, SOCK_STREAM, 0);
	if (socketFD == - 1) {
		perror("socket");
		return ERROR;
	}
	string IP = GetIpAddress();
	while (ConnectToSocket(socketFD, IP, port) < 0);  /* Try until a connection is established */
	
	int optValue = 1;
	if (setsockopt(socketFD, IPPROTO_TCP, TCP_NODELAY, &optValue, sizeof(optValue)) < 0) {  /* Set no delay option for TCP socket */
		perror("setsockopt");
		return ERROR;
	}
	return OK;
}

void DeleteSocket(const int& socketFD) {
	close(socketFD);  /* Delete socket */
}

bool SendBloomFilters(const int& socketFD, const unsigned int& bufferSize, const unsigned int& sizeOfBloom, list& viruses) {
	string message;
	const listNode *node = viruses.GetHead();
	while (node != NULL) {
		const nodeData *dataPtr = node->GetData();
		const virus *vrsPtr = dynamic_cast<const virus *>(dataPtr);
		string virusName = vrsPtr->GetName();
		message = virusName;
		if (SendMessageReceiveACK(socketFD, message, bufferSize) == ERROR)  /* Send virusName */
			return ERROR;
		
		string bitArray = BitArrayToString(vrsPtr->GetBloom().GetBitArray(), sizeOfBloom);
		message = bitArray;
		if (SendMessageReceiveACK(socketFD, message, bufferSize) == ERROR)  /* Send bitArray of virus' bloom */
			return ERROR;
		
		node = node->GetNext();
	}
	message = STOP;
	if (SendMessageReceiveACK(socketFD, message, bufferSize) == ERROR)
		return ERROR;
	return OK;
}

bool SendMessageReceiveACK(const int& socketFD, const string& message, const unsigned int& bufferSize) {
	if (WriteSocket(socketFD, message, bufferSize) == ERROR) {  /* Write message to socket */
		cout << "Cannot write to socket " << socketFD << "\n";
		return ERROR;
	}
	if (message == STOP)  /* In case of STOP, there won't be an acknowledgment */
		return OK;
	string response;
	if (ReadSocket(socketFD, response, bufferSize) == ERROR) {  /* Read acknowledgment from socket */
		cout << "Cannot read from socket " << socketFD << "\n";
		return ERROR;
	}
	if (response != ACK) {
		cout << "Didn't receive acknowledgment\n";
		return ERROR;
	}
	return OK;
}

bool ReceiveMessageSendACK(const int& socketFD, string& message, const unsigned int& bufferSize) {
	if (ReadSocket(socketFD, message, bufferSize) == ERROR) {  /* Read message from socket */
		cout << "Cannot read from socket " << socketFD << "\n";
		return ERROR;
	}
	if (message == STOP)  /* In case of STOP, don't send acknowledgment */
		return OK;
	string response = ACK;
	if (WriteSocket(socketFD, response, bufferSize) == ERROR) {  /* Write acknowledgment to socket */
		cout << "Cannot write to socket " << socketFD << "\n";
		return ERROR;
	}
	return OK;
}

bool ReadSocket(const int& socketFD, string& message, const unsigned int& bufferSize) {
	message = "";
	string messageEnd = END_OF_MESSAGE;
	char *buffer = new char[bufferSize];
	int bytes;
	while (bytes = read(socketFD, buffer, bufferSize)) {  /* Read at most bufferSize bytes */
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

bool WriteSocket(const int& socketFD, const string& message, const unsigned int& bufferSize) {	
	char *buffer = new char[bufferSize];
	for (unsigned int send = 0; send < message.length();) {  /* Send message through buffer */
		unsigned int size = bufferSize;
		if (send + bufferSize > message.length())
			size = message.length() - send;
		memcpy(buffer, message.substr(send, size).c_str(), size);
		if (write(socketFD, buffer, size) != size) {  /* Write size bytes at each time */
			perror("write");
			delete[] buffer;
			return ERROR;
		}
		send += size;  /* Sent bytes so far */
	}
	string messageEnd = END_OF_MESSAGE;
	memcpy(buffer, messageEnd.c_str(), messageEnd.length());
	write(socketFD, buffer, messageEnd.length());  /* Write end of message */
	delete[] buffer;
	return OK;
}

string BitArrayToString(const char *bitArray, const unsigned int& size) {
	string bitString = "";
	for (unsigned int i = 0; i < size; i++)
		bitString += bitArray[i];
	return bitString;
}

bool IsRegularFile(const string& path) {
	struct stat statBuf;
	if (stat(path.c_str(), &statBuf))
		return 0;
	return S_ISREG(statBuf.st_mode);
}

bool ProduceFromDirectory(const string& path, list& oldCountryFiles) {
	DIR *dir;
  struct dirent *dirEntry;
	dir = opendir(path.c_str());
	if (dir) {
		while (dirEntry = readdir(dir)) {
			string entryName = dirEntry->d_name;
			string newPath = path + "/" + entryName;
			if (IsRegularFile(newPath)) {
				country countryFileTemp(entryName);
				if (oldCountryFiles.Search(countryFileTemp) == NULL) {  /* If it's the first encounter of this country file, put it in the buffer */
					place(&pool, entryName);
//					cout << "producer: " << entryName << "\n";
          pthread_cond_signal(&cond_nonempty);  /* Let consumers know there are available items */
					oldCountryFiles.Insert(countryFileTemp);  /* Add it to processed country files */
				}
			}
		}
		closedir(dir);
		return OK;
	}
	return ERROR;
}

bool InputFromFile(const string& path, hashTable& citizens, list& countries, list& viruses, const unsigned int& bloomSize) {
	ifstream file(path.c_str());
	if (file.is_open()) {
		string line;
		while(getline(file, line)) {
			if (InputFromLine(line, citizens, countries, viruses, bloomSize) == ERROR)
				cout << "ERROR IN RECORD " << line << "\n";
		}
		file.close();
		return OK;
	}
	return ERROR;
}

bool InputFromLine(string line, hashTable& citizens, list& countries, list& viruses, const unsigned int& bloomSize) {
	string citizenID = CreateAttribute(line);
	string firstName = CreateAttribute(line);
	string lastName = CreateAttribute(line);
	string countryName = CreateAttribute(line);
	unsigned int age = atoi(CreateAttribute(line).c_str());
	string virusName = CreateAttribute(line);
	string vaccinated = CreateAttribute(line);
	
	country *cntrPtr = RegisterCountry(countryName, countries);
	citizen *ctznPtr = RegisterCitizen(citizenID, firstName, lastName, *cntrPtr, age, citizens);
	virus *vrsPtr = RegisterVirus(virusName, bloomSize, viruses);
	
	if (vaccinated == "YES") {
		tm date = CreateDate(line);
		vrsPtr->Vaccinated(*ctznPtr, date);
	}
	else if (vaccinated == "NO" || vaccinated == "NO\r") {  /* Works for both LF and CRLF file formats */
		if (line != "")
			return ERROR;
		vrsPtr->NotVaccinated(*ctznPtr);
	}
	else
		return ERROR;
	return OK;
}

country *RegisterCountry(const string& countryName, list& countries) {
	country cntrTemp(countryName);
	nodeData *dataPtr = countries.Search(cntrTemp);
	if (dataPtr == NULL) {
		countries.Insert(cntrTemp);
		dataPtr = countries.Search(cntrTemp);
	}
	country *cntrPtr = dynamic_cast<country *>(dataPtr);
	return cntrPtr;
}

citizen *RegisterCitizen(const string& citizenID, const string& firstName, const string& lastName, const country& cntr, const unsigned int& age, hashTable& citizens) {
	citizen ctznTemp(citizenID, firstName, lastName, cntr, age);
	nodeData *dataPtr = citizens.Search(ctznTemp);
	if (dataPtr == NULL) {
		citizens.Insert(ctznTemp);
		dataPtr = citizens.Search(ctznTemp);
	}
	citizen *ctznPtr = dynamic_cast<citizen *>(dataPtr);
	return ctznPtr;
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

string DateToString(const tm& date) {
	string dateStr = to_string(date.tm_mday) + "-" + to_string(1 + date.tm_mon) + "-" + to_string(1900 + date.tm_year);
	return dateStr;
}

void PrintDate(const tm& date) {
	cout << date.tm_mday << "-" << 1 + date.tm_mon << "-" << 1900 + date.tm_year;
}

void ReceiveCommands(const int& socketFD, const unsigned int& bufferSize, const unsigned int& sizeOfBloom, const string& inputDir, hashTable& citizens, list& countries, list& viruses, list& oldCountryFiles) {
	unsigned int totalRequests = 0;
	unsigned int acceptedRequests = 0;
	string command;
	while (1) {
		if (ReceiveMessageSendACK(socketFD, command, bufferSize) == ERROR)
			return;
		unsigned int argCount = CountArguments(command);
		istringstream sstream(command);
		string function, argument1, argument2, argument3, argument4;
		sstream >> function >> argument1 >> argument2 >> argument3 >> argument4;
		if (function == "/travelRequest") {
			if (argCount == 4)
				TravelRequest(socketFD, bufferSize, citizens, viruses, totalRequests, acceptedRequests, argument1, argument2, argument3, argument4);
			else
				PrintProperUse();
		}
		else if (function == "/addVaccinationRecords") {
			if (argCount == 1)
				AddVaccinationRecords(socketFD, bufferSize, sizeOfBloom, inputDir, countries, viruses, oldCountryFiles, argument1);
			else
				PrintProperUse();
		}
		else if (function == "/searchVaccinationStatus") {
			if (argCount == 1)
				SearchVaccinationStatus(socketFD, bufferSize, citizens, viruses, argument1);
			else
				PrintProperUse();
		}
		else if (function == "/exit") {
			if (argCount == 0) {
				Exit(socketFD, bufferSize, countries, totalRequests, acceptedRequests);
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
				<< "/travelRequest citizenID date countryFrom virusName\n"
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

void TravelRequest(const int& socketFD, const unsigned int& bufferSize, hashTable& citizens, list& viruses, unsigned int& totalRequests, unsigned int& acceptedRequests, const string& citizenID, const string& dateStr, const string& countryFrom, const string& virusName) {
	string message;
	if (ReceiveMessageSendACK(socketFD, message, bufferSize) == ERROR)
		return;
	if (message != STOP)
		return;	
	totalRequests++;  /* Increase total requests */
	country cntrTemp("");
	citizen ctznTemp(citizenID, "", "", cntrTemp, 0);
	nodeData* dataPtr = citizens.Search(ctznTemp);
	citizen *ctznPtr = dynamic_cast<citizen *>(dataPtr);
	if (ctznPtr != NULL && ctznPtr->GetCountry().GetName() != countryFrom) {  /* Check that countryFrom is valid for this citizen */
		message = "NO";
	}
	else {
		virus vrsTemp(virusName, 0);
		dataPtr = viruses.Search(vrsTemp);
		if (dataPtr == NULL)  /* Not registered virus */
			message = "NO";
		else {
			virus *vrsPtr = dynamic_cast<virus *>(dataPtr);
			const tm *date = vrsPtr->SearchVaccinatedPersons(citizenID);
			if (date == NULL)  /* Not vaccinated citizen */
				message = "NO";
			else {  /* Vaccinated citizen */
				string vaccineDateStr = DateToString(*date);
				message = "YES " + vaccineDateStr;
				tm vaccineDate = CreateDate(vaccineDateStr);
				string travelDateStr = dateStr;
				tm travelDate = CreateDate(travelDateStr);
				double difSeconds = difftime(mktime(&travelDate), mktime(&vaccineDate));  /* Compare travel date to vaccine date */
				if (difSeconds >= 0 && difSeconds / 60 / 60 / 24 / 30 < 6)  /* Difference in seconds -> minutes -> hours -> days -> months */
					acceptedRequests++;  /* Accept request if difference is less than 6 months (180 days) */
			}
		}
	}
	if (SendMessageReceiveACK(socketFD, message, bufferSize) == ERROR)
		return;
	message = STOP;
	if (SendMessageReceiveACK(socketFD, message, bufferSize) == ERROR)
		return;
}

void AddVaccinationRecords(const int& socketFD, const unsigned int& bufferSize, const unsigned int& sizeOfBloom, const string& inputDir, list& countries, list& viruses, list& oldCountryFiles, const string& countryFrom) {
	string message;
	if (ReceiveMessageSendACK(socketFD, message, bufferSize) == ERROR)
		return;
	if (message != STOP)
		return;
	country cntrTemp(countryFrom);
	nodeData *dataPtr = countries.Search(cntrTemp);
	if (dataPtr == NULL)
		return;
	if (inputDir != "") {
		string path = "./" + inputDir + "/" + countryFrom;
		if (ProduceFromDirectory(path, oldCountryFiles) == ERROR)  /* Add files from given country's directory to cyclic buffer */
			return;
	}
	if (SendBloomFilters(socketFD, bufferSize, sizeOfBloom, viruses) == ERROR)
		return;
}

void SearchVaccinationStatus(const int& socketFD, const unsigned int& bufferSize, hashTable& citizens, list& viruses, const string& citizenID) {
	string message;
	if (ReceiveMessageSendACK(socketFD, message, bufferSize) == ERROR)
		return;
	if (message != STOP)
		return;
	country cntrTemp("");
	citizen ctznTemp(citizenID, "", "", cntrTemp, 0);
	nodeData* dataPtr = citizens.Search(ctznTemp);
	if (dataPtr != NULL) {  /* Found citizen with given citizenID */
		citizen *ctznPtr = dynamic_cast<citizen *>(dataPtr);
		message = citizenID + " " + ctznPtr->GetFirstName() + " " + ctznPtr->GetLastName() + " " + ctznPtr->GetCountry().GetName();
		if (SendMessageReceiveACK(socketFD, message, bufferSize) == ERROR)  /* Send citizenID, firstName, lastName, country */
			return;
		message = "AGE " + to_string(ctznPtr->GetAge());
		if (SendMessageReceiveACK(socketFD, message, bufferSize) == ERROR)  /* Also send age*/
			return;
		
		const listNode *node = viruses.GetHead();
		unsigned int count = 0;
		while (node != NULL) { /* Check his vaccine status for each virus */
			const nodeData *dataPtr = node->GetData();
			const virus *vrsPtr = dynamic_cast<const virus *>(dataPtr);
			const tm *date = vrsPtr->SearchVaccinatedPersons(citizenID);
			if (date != NULL) {  /* Vaccinated against this virus */
				message = vrsPtr->GetName() + " VACCINATED ON " + DateToString(*date);
				if (SendMessageReceiveACK(socketFD, message, bufferSize) == ERROR)
					return;
				count++;
			}
			else {  /* Not vaccinated against this virus */
				message = vrsPtr->GetName() + " NOT YET VACCINATED";
				if (SendMessageReceiveACK(socketFD, message, bufferSize) == ERROR)
					return;
				count++;
			}
			node = node->GetNext();
		}
		if (count == 0) {
			message = "NOT VACCINATED AGAINST ANY VIRUS";
			if (SendMessageReceiveACK(socketFD, message, bufferSize) == ERROR)
				return;
		}
	}
	message = STOP;
	if (SendMessageReceiveACK(socketFD, message, bufferSize) == ERROR)
		return;
}

void Exit(const int& socketFD, const unsigned int& bufferSize, list& countries, const unsigned int& totalRequests, const unsigned int& acceptedRequests) {
	string message;
	if (ReceiveMessageSendACK(socketFD, message, bufferSize) == ERROR)
		return;
	if (message != STOP)
		return;
	CreateLogFile(countries, totalRequests, acceptedRequests);
	message = "DONE";
	if (SendMessageReceiveACK(socketFD, message, bufferSize) == ERROR)  /* Let parent know that log file has been created */
		return;
	message = STOP;
	if (SendMessageReceiveACK(socketFD, message, bufferSize) == ERROR)
		return;
}

void CreateLogFile(list& countries, const unsigned int& totalRequests, const unsigned int& acceptedRequests) {
	string filename = "log_file." + to_string(getpid());
	ofstream file(filename);
	const listNode *node = countries.GetHead();
	while (node != NULL) {  /* Write all countries that monitor is aware of */
		const nodeData *dataPtr = node->GetData();
		const country *cntrPtr = dynamic_cast<const country *>(dataPtr);
		if (cntrPtr != NULL)
			file << cntrPtr->GetName() << "\n";
		node = node->GetNext();
	}
	file << "TOTAL TRAVEL REQUESTS " << totalRequests << "\n";
	file << "ACCEPTED " << acceptedRequests << "\n";
	file << "REJECTED " << (totalRequests - acceptedRequests) << "\n";
	file.close();
}
