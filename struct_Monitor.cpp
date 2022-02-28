#include "struct_Monitor.h"

using namespace std;

monitor::monitor(const int& monitorID, const int& socketFD, const int& port, const int& newSocketFD, const pid_t& pid) : monitorID(monitorID), socketFD(socketFD), port(port), newSocketFD(newSocketFD), pid(pid) {
}

monitor::monitor(const monitor& mntr) : monitorID(mntr.monitorID), socketFD(mntr.socketFD), port(mntr.port), newSocketFD(mntr.newSocketFD), pid(mntr.pid) {
}

int monitor::GetMonitorID() const {
	return monitorID;
}

int monitor::GetSocketFD() const {
	return socketFD;
}

int monitor::GetPort() const {
	return port;
}

int monitor::GetNewSocketFD() const {
	return newSocketFD;
}

pid_t monitor::GetPID() const {
	return pid;
}

void monitor::SetNewSocketFD(const int& newSocketFD) {
	this->newSocketFD = newSocketFD;
}

void monitor::SetPID(const pid_t& pid) {
	this->pid = pid;
}

const list& monitor::GetCountries() const {
	return countries;
}

const country *monitor::GetCountry(const std::string& countryName) const {
	country cntrTemp(countryName);
	nodeData *dataPtr = countries.Search(cntrTemp);
	const country *cntrPtr = dynamic_cast<const country *>(dataPtr);
	return cntrPtr;
}

void monitor::AddCountry(const string& countryName) {
	if (GetCountry(countryName) == NULL) {
		country cntrTemp(countryName);
		countries.Insert(cntrTemp);
	}
}
