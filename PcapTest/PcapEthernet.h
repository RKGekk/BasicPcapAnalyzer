#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <functional>

#include "pcap_hdr_t.h"
#include "pcaprec_hdr_t.h"
#include "PcapEthernetUnit.h"

class PcapEthernet {
	pcap_hdr_t m_hdr;
	std::vector<PcapEthernetUnit> m_pcapUnits;
	std::string m_pcapFileName;
	bool m_initialized;

public:
	PcapEthernet();
	PcapEthernet(std::string pcapFileName);

	~PcapEthernet();

	bool initialize();
	void iterate(std::function<void(const PcapEthernetUnit&)> fn);

private:
	void getEthernetUnit(char* data, pcaprec_hdr_t phdr, PcapEthernetUnit& out);
	unsigned short extract_littleend16(const char* buf);

	friend std::ostream& operator<<(std::ostream& os, const PcapEthernet& p);
};

std::ostream& operator<<(std::ostream& os, const PcapEthernet& p);
std::ostream& operator<<(std::ostream& os, const PcapEthernetUnit& p);