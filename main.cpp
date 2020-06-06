#include <iostream>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")
#include <winsock2.h>
#include <string>
#include <bitset>
#include <sstream>
#include <Windns.h>
#include <map>
#include <vector>
#include <thread>

#pragma warning(disable:4996)

//Кеш доменов
std::map<std::string, std::vector<std::string>> domainsCache;
std::map<std::string, std::vector<std::string>> domainsNSCache;

std::string getDomainFromDNSRequest(char* str);
std::string getTypeRecord(char* str);
std::string getStringFromHex(char* str, int count, int& pivot);

std::string getIPs(std::string domain)
{
	std::string result = "";
	for (auto ip : domainsCache[domain])
	{
		result.append(ip);
		result += '\n';
	}
	std::cout << result;

	return result;
}

std::string getNSes(std::string domain)
{
	std::string result = "";
	for (auto ip : domainsNSCache[domain])
	{
		result.append(ip);
		result += '\n';
	}
	std::cout << result;

	return result;
}

void getDataForDomainNS(std::string domain)
{
	PDNS_RECORD res;
	DnsQuery_A(domain.c_str(), DNS_TYPE_NS, DNS_QUERY_STANDARD, NULL, &res, NULL);
	std::vector <std::string> nsServers;
	
	while (res)
	{
		std::stringstream StrStream;
		PWSTR ns = res->Data.NS.pNameHost;
		StrStream << (CHAR*)ns;
		nsServers.push_back(StrStream.str());
		res = res->pNext;
	}

	domainsNSCache[domain] = nsServers;
}

void getDataForDomain(std::string domain)
{
	PDNS_RECORD res;
	DnsQuery_A(domain.c_str(), DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &res, NULL);
	IN_ADDR ipaddr;
	std::vector <std::string> ips;
	while (res)
	{
		ipaddr.S_un.S_addr = res->Data.A.IpAddress;
		std::string ip(inet_ntoa(ipaddr));
		ips.push_back(ip);
		res = res->pNext;
	}
	domainsCache[domain] = ips;
}

DWORD getTtlFromDomainNS(std::string domain)
{
	PDNS_RECORD res;
	DNS_STATUS r = DnsQuery_A(domain.c_str(), DNS_TYPE_NS, DNS_QUERY_STANDARD, NULL, &res, NULL);
	std::cout << "TTL: " << res->dwTtl;
	return res->dwTtl;
}

void deleteDomainNSAfterTtlDie(std::string domain, int ttl)
{
	if (ttl == 0)
		ttl = 2;
	Sleep(ttl * 1000);
	std::cout << domain << " - TTL is out of date [NS]\n";
	domainsCache.erase(domain);
	getDataForDomainNS(domain);
	std::cout << domain << " - TTL was updated [NS]\n";
	deleteDomainNSAfterTtlDie(domain, getTtlFromDomainNS(domain));
}

DWORD getTtlFromDomain(std::string domain)
{
	PDNS_RECORD res;
	DNS_STATUS r = DnsQuery_A(domain.c_str(), DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &res, NULL);
	std::cout << "TTL: " << res->dwTtl;
	return res->dwTtl;
}

void deleteDomainAfterTtlDie(std::string domain, int ttl)
{
	if (ttl == 0)
		ttl = 2;
	Sleep(ttl * 1000);
	std::cout << domain << " - TTL is out of date [IP]\n";
	domainsCache.erase(domain);
	getDataForDomain(domain);
	std::cout << domain << " - TTL was updated [IP]\n";
	deleteDomainAfterTtlDie(domain, getTtlFromDomain(domain));
}

int main()
{
	setlocale(LC_ALL, "Russian");

	//startup
	WSAData data;
	WORD DLLVersion = MAKEWORD(2, 1);
	if (WSAStartup(DLLVersion, &data) != 0)
	{
		std::cout << "Error with lib";
		return 1;
	}

	SOCKADDR_IN addr;
	int sizeofaddr = sizeof(addr);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(53);
	addr.sin_family = AF_INET;

	SOCKET sListen = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	bind(sListen, (SOCKADDR*)&addr, sizeofaddr);
	listen(sListen, SOMAXCONN);

	char msg[256];
	sockaddr client;
	int sizeofclient = sizeof(client);
	
	while (true)
	{
		int request = recvfrom(sListen, msg, 256, 0, &client, &sizeofclient);

		if (request == SOCKET_ERROR)
		{
			std::cout << "error!";
			continue;
		}

		std::cout << "Request received: " << msg << '\n';
		std::string domain = getDomainFromDNSRequest(msg);
		std::cout << "Domain request: "<< domain << '\n';
		std::string type = getTypeRecord(msg);
		std::cout << "Type of source record: " << type << '\n';

		
		if (type == "NS")
		{
			if (domainsNSCache.count(domain) == 1)
			{
				std::cout << "Domain in NS cache\n";
				std::string result = getNSes(domain);
				result += '\0';
				sendto(sListen, result.c_str(), result.length(), 0, &client, sizeofclient);
			}
			
			else
			{
				std::cout << "No domain in NS cache\n";
				getDataForDomainNS(domain);
				std::string result = getNSes(domain);
				result += '\0';
				sendto(sListen, result.c_str(), result.length(), 0, &client, sizeofclient);
				std::thread* demon = new std::thread(deleteDomainNSAfterTtlDie, domain, getTtlFromDomainNS(domain));
			}
		}
		
		else {
			
			
			if (domainsCache.count(domain) == 1)
			{
				std::cout << "Domain in IP cache\n";
				std::string result = getIPs(domain);
				result += '\0';
				sendto(sListen, result.c_str(), result.length(), 0, &client, sizeofclient);
			}
			
			else
			{
				std::cout << "No domain in IP cache\n";
				getDataForDomain(domain);
				std::string result = getIPs(domain);
				result += '\0';
				sendto(sListen, result.c_str(), result.length(), 0, &client, sizeofclient);
				std::thread* demon = new std::thread(deleteDomainAfterTtlDie, domain, getTtlFromDomain(domain));
			}
		}

		std::cout << std::endl << std::endl;
	}
}

std::string getDomainFromDNSRequest(char* str)
{
	int pivot = 36; 
	std::string domain = "";
	
	std::string length = "";
	length += str[pivot];
	length += str[++pivot];
	int lengthDomainName = std::stoul(length, nullptr, 16);

	
	domain.append(getStringFromHex(str, lengthDomainName, pivot));

	domain += '.';

	
	pivot++;
	length = "";
	length += str[pivot];
	length += str[++pivot];
	int lengthDomainArea = std::stoul(length, nullptr, 16);
	domain.append(getStringFromHex(str, lengthDomainArea, pivot));

	return domain;
}

std::string getTypeRecord(char* str)
{
	std::string msg(str);
	std::string number = "";

	number += msg[msg.length() - 9];
	number += msg[msg.length() - 8];

	if (number == "02")
		return "NS";
	if (number == "01")
		return "A";
}

std::string getStringFromHex(char* str, int count, int &pivot)
{
	std::string result = "";

	while (count != -1)
	{
		pivot++;
		if (str[pivot] == ' ')
		{
			count--;
		}
		else
		{
			std::string hexLetter = "";
			hexLetter += str[pivot];
			pivot++;
			hexLetter += str[pivot];
			int intLetter = std::stoul(hexLetter, nullptr, 16);
			result += (char)intLetter;
		}
	}

	return result;
}
