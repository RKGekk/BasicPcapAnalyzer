#include "PcapEthernet.h"

#include <fstream>

PcapEthernet::PcapEthernet() {
	m_initialized = false;
}

PcapEthernet::PcapEthernet(std::string pcapFileName) {
	m_pcapFileName = pcapFileName;
	m_initialized = false;
}

PcapEthernet::~PcapEthernet() {
	for(const PcapEthernetUnit& u : m_pcapUnits) {
		delete[] u.etherData;
	}
}

bool PcapEthernet::initialize() {
	if(m_initialized || m_pcapFileName.empty()) {
		return false;
	}

	std::fstream finout;
	finout.open(m_pcapFileName, std::ios_base::in | std::ios_base::out | std::ios_base::binary);
	if (!finout.is_open()) {
		return false;
	}
	finout.seekg(0);

	finout.read((char*)&m_hdr, sizeof pcap_hdr_t);

	if (m_hdr.version_major != 2 && m_hdr.version_minor != 4 && m_hdr.magic_number != 2712847316 && m_hdr.network != LinkLayerType::DLT_EN10MB) {
		return false;
	}

	while(finout.peek() != std::char_traits<char>::eof()) {
		pcaprec_hdr_t phdr;
		finout.read((char*)&phdr, sizeof pcaprec_hdr_t);

		char* packet = new char[phdr.incl_len];
		finout.read(packet, phdr.incl_len);

		PcapEthernetUnit unit;
		getEthernetUnit(packet, phdr, unit);
		m_pcapUnits.push_back(unit);
	}

	m_initialized = true;
	return true;
}

void PcapEthernet::iterate(std::function<void(const PcapEthernetUnit&)> fn) {
	for(const PcapEthernetUnit& eu : m_pcapUnits) {
		fn(eu);
	}
}

void PcapEthernet::getEthernetUnit(char* data, pcaprec_hdr_t phdr, PcapEthernetUnit& out) {

	out.phdr = phdr;
	out.etherData = data;

	size_t packLength = (size_t)phdr.incl_len;
	std::copy(data + 0, data + 6, out.destination.bytes);
	std::copy(data + 6, data + 12, out.source.bytes);
	out.protocol = (EtherType)extract_littleend16(data + 12);
	out.size = packLength - 14 - 4;
	std::copy(data + packLength - 4, data + packLength, out.frameCheckSequence.bytes);

	if(out.protocol == EtherType::ET_IPv6 || out.protocol == EtherType::ET_IPv4) {
		out.payloadData = data + 14;
	}
}

unsigned short PcapEthernet::extract_littleend16(const char* buf) {
	unsigned short l = ((unsigned short)buf[0]) << 8;
	unsigned short r = (((unsigned short)buf[1]) << 0) & 0xFF;
	return l | r;
}

std::ostream& operator<<(std::ostream& os, const PcapEthernet& m) {
	if(!m.m_initialized) {
		return os << "Pcap Ethernet processor is not initialized!" << std::endl;
	}

	std::ios::fmtflags oldFlags = os.flags();

	os << "LLP is IEEE 802.3 Ethernet" << std::endl;
	for(const PcapEthernetUnit& pu : m.m_pcapUnits) {
		os << pu << std::endl;
	}

	os.flags(oldFlags);
	return os;
}

std::ostream& operator<<(std::ostream& os, const PcapEthernetUnit& pu) {
	std::ios::fmtflags oldFlags = os.flags();

	time_t packTime = (time_t)pu.phdr.ts_sec;
	size_t packLength = (size_t)pu.phdr.incl_len;
	os << "PDU capture time: " << std::put_time(std::localtime(&packTime), "%F %T") << std::endl;
	os << "PDU length bytes: " << packLength << std::endl;

	int rowNum = 0;
	int colNum = 0;
	std::cout << std::setw(3) << std::setfill('0') << rowNum << " : ";
	for (unsigned i = 0; i < packLength; ++i) {

		std::cout << std::hex << std::setw(2) << std::setfill('0') << (static_cast<int>(pu.payloadData[i]) & 0xFF) << std::dec;
		if ((colNum + 1) % 16) {
			if ((colNum + 1) % 8 == 0) {
				std::cout << " ";
			}
			std::cout << " ";
			++colNum;
		}
		else {
			std::cout << std::endl;
			colNum = 0;
			++rowNum;
			std::cout << std::setw(3) << rowNum << " : ";
		}
	}
	std::cout << std::endl;
	
	os.flags(oldFlags);
	return os;
}
