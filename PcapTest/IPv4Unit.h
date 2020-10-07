#pragma once
#include <algorithm>

#include "PcapEthernetUnit.h"
#include "NextHeader.h"
#include "IPv4.h"

class IPv4Unit {
public:
	unsigned char m_version;
	unsigned char m_headerLength;
	unsigned char m_trafficType;
	unsigned char m_diffServices;
	unsigned char m_expCongestionNotify;
	unsigned short m_totalLength;
	unsigned short m_identification;
	unsigned char m_fragmentationFlag;
	unsigned short m_fragmentatOffset;
	unsigned char m_ttl;
	NextHeader m_nextHeader;
	unsigned short m_checkSum;
	IPv4 m_sourceAddress;
	IPv4 m_destinationAddress;

	bool m_initialized;
	char* m_payloadData;

	IPv4Unit();

	bool initialize(char* EtherData, size_t length);
	bool initialize(const PcapEthernetUnit& ethernetUnit);
};