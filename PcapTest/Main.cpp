// ����������� ���������� ���������� ��� �������� ���������� UDP / IP - ������� � ����� ������� PCAP.
// 
// �������������
// �������������� ���������� :
// ���������� ������ ����������� ����� �� UDP / IP ������(��������, TCP / IP)
// ���������� ������ ����� ����������� ����������� UDP - ������ �� IP - ������ � / ��� ����� ����������
// ���������� ������ �������� �� ����� ���������� ������� PCAP ����� � ����������������� ���� �� ��������� ����������� :
// <����� ������ ���������� �� �������> <����� ��������� : ���� ���������> <����� ���������� : ���� ����������> <���������� �������> <����� ����� ������ � �������>
// ���������� ��������� IPv4
// �������������
// ���������������� ���������� :
// ����������� ���������� ������ ��������� ��������� ���
// ��� ������ ���������� � ������� ����������� g++
// ���������� � ��������� �++ �� �������������
// ������ ������ ���� ����������� � ������������� cmake
// ����������� �� ������������� ��������� ��������� ���
// ��� ������ ���� ������� ���������, ������ ����� ����������� � ����������
// �������������
// ������� ��������� :
// ������������ ��������� :
// ���� � PCAP - �����
// ������������ ��������� :
// ������ �� IP - ������ ����������
// ������ �� ����� ����������

#include <iostream>
#include <fstream>
#include <iomanip>
#include <chrono>
#include <ctime>

#include "pcap_hdr_t.h"
#include "pcaprec_hdr_t.h"
#include "LinkLayerType.h"
#include "PcapEthernet.h"
#include "EtherType.h"
#include "IPv6Unit.h"
#include "IPv4Unit.h"
#include "NextHeader.h"

int main() {

	
	const char* fileName = "ttt.pcap";
	//const char* fileName = "dhcp1.pcap";
	PcapEthernet capture(fileName);
	if(!capture.initialize()) {
		std::cout << "Initialization failed" << std::endl;
		return 0;
	}
	std::cout << capture << std::endl;

	int counter = 0;
	int UDPCounter = 0;
	capture.iterate([&](const PcapEthernetUnit& eu) {
		if(eu.protocol == EtherType::ET_IPv6) {
			IPv6Unit ipUnit;
			ipUnit.initialize(eu);
			std::cout << counter++ << " : IPv" << (int)ipUnit.m_version << std::endl;
			if(ipUnit.m_nextHeader == NextHeader::NH_UDP) {
				++UDPCounter;
			}
		}
		if (eu.protocol == EtherType::ET_IPv4) {
			IPv4Unit ipUnit;
			ipUnit.initialize(eu);
			std::cout << counter++ << " : IPv" << (int)ipUnit.m_version << std::endl;
			if (ipUnit.m_nextHeader == NextHeader::NH_UDP) {
				++UDPCounter;
			}
		}
	});

	std::cout << "Total UDP packets: " << UDPCounter << std::endl;

	return 0;
}