#pragma once
#include <algorithm>

#include "PcapEthernetUnit.h"
#include "NextHeader.h"
#include "IPv6.h"

class IPv6Unit {
public:
	unsigned char m_version;
	unsigned char m_trafficType;
	unsigned char m_diffServices;
	unsigned char m_expCongestionNotify;
	unsigned int m_flowLabel;
	unsigned short m_payloadLength;
	NextHeader m_nextHeader;
	unsigned char m_hopLimit;
	IPv6 m_sourceAddress;
	IPv6 m_destinationAddress;
	bool m_initialized;
	char* m_payloadData;

	IPv6Unit();

	bool initialize(char* EtherData, size_t length);
	bool initialize(const PcapEthernetUnit& ethernetUnit);
};