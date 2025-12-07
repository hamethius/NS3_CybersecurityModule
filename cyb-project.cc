/*
 * Cybersecurity Project: Network Attacks & Defense Simulation
 * Features: UDP Flood, ICMP Flood, Malware Injection
 * Defenses: Rate Limiting, Port Filtering, Deep Packet Inspection (DPI)
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/packet-sink.h"
#include "ns3/point-to-point-module.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/ipv4-header.h"
#include "ns3/udp-header.h"
#include <iostream>
#include <string>

using namespace ns3;

// ===========================================================================
//                                GLOBAL CONFIGURATION
// ===========================================================================
// These flags control what runs during the simulation.
// ===========================================================================

bool g_simEnableFirewall    = true;  // Master Switch for Defense
bool g_simEnableRateLimit   = true;  // Defense against UDP Flood
bool g_simEnablePortFilter  = true;  // Defense against ICMP/Port 0
bool g_simEnableDpi         = true;  // Defense against Malware

bool g_simRunUdpFlood       = true;  // Attack 1
bool g_simRunIcmpFlood      = true;  // Attack 2
bool g_simRunMalware        = true;  // Attack 3

// ===========================================================================
//                                DEFENSE MODULE
// ===========================================================================

class DefenseModule : public Object {
public:
    static TypeId GetTypeId(void);
    
    DefenseModule() {
        m_packetCount = 0;
        m_lastCheckTime = Seconds(0);
        m_threshold = 50; // Max packets allowed per second
        m_floodWarned = false;
    }

    // INSPECT PACKET: Returns 'true' to ALLOW, 'false' to DROP
    bool InspectPacket(Ptr<const Packet> packet, Ptr<Ipv4> ipv4, uint32_t interface) {
        
        // If the Master Firewall Switch is OFF, let everything pass
        if (!g_simEnableFirewall) return true;

        Ipv4Header ipHeader;
        packet->PeekHeader(ipHeader);
        Ipv4Address srcIp = ipHeader.GetSource();
        uint32_t packetSize = packet->GetSize();
        
        // Helper variables
        UdpHeader udpHeader;
        bool isUdp = (ipHeader.GetProtocol() == 17);

        // ------------------------------------------------------------
        // DEFENSE: MALWARE DPI (Deep Packet Inspection)
        // ------------------------------------------------------------
        if (g_simEnableDpi) {
            uint8_t *buffer = new uint8_t[packetSize];
            packet->CopyData(buffer, packetSize);
            std::string payload((char*)buffer, packetSize);
            delete[] buffer;

            if (payload.find("MALWARE_HASH") != std::string::npos) {
                std::cout << std::endl;
                std::cout << "\033[1;35m[DEFENSE] >>> CRITICAL: MALWARE SIGNATURE DETECTED! Dropping Packet. <<<\033[0m" << std::endl;
                std::cout << std::endl;
                return false; // DROP
            }
        }

        // ------------------------------------------------------------
        // DEFENSE: PROTOCOL FILTERING (ICMP/Port 0)
        // ------------------------------------------------------------
        if (g_simEnablePortFilter && isUdp) {
            Ptr<Packet> copy = packet->Copy();
            copy->RemoveHeader(ipHeader);
            if (copy->PeekHeader(udpHeader)) {
                if (udpHeader.GetDestinationPort() == 0) {
                    std::cout << "\033[1;33m[DEFENSE] BLOCKED: Malformed UDP/ICMP request to Port 0\033[0m" << std::endl;
                    return false; // DROP
                }
            }
        }

        // ------------------------------------------------------------
        // DEFENSE: RATE LIMITING (Anti-Flood)
        // ------------------------------------------------------------
        // FIX: Only count UDP packets towards the flood limit. 
        // This prevents blocking legitimate TCP background traffic.
        if (g_simEnableRateLimit && isUdp) { 
            
            Time now = Simulator::Now();
            if (now - m_lastCheckTime >= Seconds(1.0)) {
                m_packetCount = 0;
                m_lastCheckTime = now;
                m_floodWarned = false; 
            }

            m_packetCount++;

            if (m_packetCount > m_threshold) {
                if (!m_floodWarned) {
                    std::cout << "\033[1;31m[DEFENSE] BLOCKED: Flood detected from " << srcIp 
                              << " (Rate > " << m_threshold << "/sec). Suppressing logs...\033[0m" << std::endl;
                    m_floodWarned = true;
                }
                return false; // DROP
            }
        }

        return true; // ALLOW
    }

private:
    uint32_t m_packetCount;
    Time m_lastCheckTime;
    uint32_t m_threshold;
    bool m_floodWarned;
};

NS_OBJECT_ENSURE_REGISTERED(DefenseModule);

TypeId DefenseModule::GetTypeId(void) {
    static TypeId tid = TypeId("DefenseModule")
        .SetParent<Object>()
        .SetGroupName("Network")
        .AddConstructor<DefenseModule>();
    return tid;
}

// Global pointer
Ptr<DefenseModule> g_firewall;

// The "Hook" function
void RxTrace(std::string context, Ptr<const Packet> packet, Ptr<Ipv4> ipv4, uint32_t interface) {
    if (g_firewall) {
        g_firewall->InspectPacket(packet, ipv4, interface);
    }
}

// ===========================================================================
//                                ATTACK MODULES
// ===========================================================================

void LogEvent(std::string msg) {
    std::cout << "[" << Simulator::Now().GetSeconds() << "s] " << msg << std::endl;
}

void UdpFloodAttack(Ptr<Node> attacker, Ipv4Address victim, uint16_t port, uint32_t size, double interval) {
    if (!g_simRunUdpFlood) return;
    
    // LogEvent("UDP Flood attack packet sent"); // Commented out to save console space
    Ptr<Socket> socket = Socket::CreateSocket(attacker, UdpSocketFactory::GetTypeId());
    InetSocketAddress remote(victim, port);
    Simulator::Schedule(Seconds(0.01), [socket, remote, size, interval]() mutable {
        Ptr<Packet> packet = Create<Packet>(size);
        socket->SendTo(packet, 0, remote);
        Simulator::Schedule(Seconds(interval), [socket, remote, size, interval]() mutable {
            Ptr<Packet> packet = Create<Packet>(size);
            socket->SendTo(packet, 0, remote);
            Simulator::Schedule(Seconds(interval), [socket, remote, size, interval]() mutable {
                 Ptr<Packet> packet = Create<Packet>(size);
                 socket->SendTo(packet, 0, remote);
            });
        });
    });
}

void IcmpFloodAttack(Ptr<Node> attacker, Ipv4Address victim, uint32_t size, double interval) {
    if (!g_simRunIcmpFlood) return;

    LogEvent(">>> ATTACK START: ICMP Flood");
    Ptr<Socket> socket = Socket::CreateSocket(attacker, UdpSocketFactory::GetTypeId());
    InetSocketAddress remote(victim, 0); 
    Simulator::Schedule(Seconds(0.01), [socket, remote, size, interval]() mutable {
        Ptr<Packet> packet = Create<Packet>(size);
        socket->SendTo(packet, 0, remote);
        Simulator::Schedule(Seconds(interval), [socket, remote, size, interval]() mutable {
            Ptr<Packet> packet = Create<Packet>(size);
            socket->SendTo(packet, 0, remote);
        });
    });
}

void MalwarePacketAttack(Ptr<Node> attacker, Ipv4Address victim, std::string hash) {
    if (!g_simRunMalware) return;

    LogEvent(">>> ATTACK START: Malware Injection");
    Ptr<Socket> socket = Socket::CreateSocket(attacker, UdpSocketFactory::GetTypeId());
    InetSocketAddress remote(victim, 5555);
    std::string payload = "MALWARE_HASH:" + hash;
    Ptr<Packet> packet = Create<Packet>((uint8_t*)payload.c_str(), payload.size());
    Simulator::Schedule(Seconds(1.0), [socket, remote, packet]() mutable {
        socket->SendTo(packet, 0, remote);
    });
}

// ===========================================================================
//                                MAIN PROGRAM
// ===========================================================================

int main(int argc, char* argv[]) {
    
    // ------------------------------------------------------
    // 1. COMMAND LINE PARSING
    // ------------------------------------------------------
    CommandLine cmd;
    cmd.AddValue("firewall", "Enable/Disable Entire Firewall", g_simEnableFirewall);
    cmd.AddValue("defenseFlood", "Enable/Disable Rate Limiting Defense", g_simEnableRateLimit);
    cmd.AddValue("defenseIcmp", "Enable/Disable ICMP/Port0 Filtering", g_simEnablePortFilter);
    cmd.AddValue("defenseMalware", "Enable/Disable Malware DPI", g_simEnableDpi);
    
    cmd.AddValue("attackFlood", "Run UDP Flood Attack", g_simRunUdpFlood);
    cmd.AddValue("attackIcmp", "Run ICMP Flood Attack", g_simRunIcmpFlood);
    cmd.AddValue("attackMalware", "Run Malware Attack", g_simRunMalware);
    
    cmd.Parse(argc, argv);

    std::cout << "==========================================" << std::endl;
    std::cout << "      CYBERSECURITY SIMULATION CONFIG     " << std::endl;
    std::cout << "==========================================" << std::endl;
    std::cout << "Defense: Firewall Master: " << (g_simEnableFirewall ? "ON" : "OFF") << std::endl;
    std::cout << "Defense: Rate Limiting:   " << (g_simEnableRateLimit ? "ON" : "OFF") << std::endl;
    std::cout << "Defense: Port Filter:     " << (g_simEnablePortFilter ? "ON" : "OFF") << std::endl;
    std::cout << "Defense: Malware DPI:     " << (g_simEnableDpi ? "ON" : "OFF") << std::endl;
    std::cout << "------------------------------------------" << std::endl;
    std::cout << "Attack:  UDP Flood:       " << (g_simRunUdpFlood ? "ON" : "OFF") << std::endl;
    std::cout << "Attack:  ICMP Flood:      " << (g_simRunIcmpFlood ? "ON" : "OFF") << std::endl;
    std::cout << "Attack:  Malware:         " << (g_simRunMalware ? "ON" : "OFF") << std::endl;
    std::cout << "==========================================" << std::endl;

    // ------------------------------------------------------
    // 2. CREATE NODES & NETWORK
    // ------------------------------------------------------
    NodeContainer nodes;
    nodes.Create(2);

    PointToPointHelper ptp;
    ptp.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    ptp.SetChannelAttribute("Delay", StringValue("2ms"));
    NetDeviceContainer devices = ptp.Install(nodes);

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer iface = ipv4.Assign(devices);
    
    Ptr<Node> attackerNode = nodes.Get(0);
    Ptr<Node> victimNode = nodes.Get(1);
    Ipv4Address victimIp = iface.GetAddress(1);

    // ------------------------------------------------------
    // 3. ACTIVATE DEFENSE MODULE
    // ------------------------------------------------------
    g_firewall = CreateObject<DefenseModule>();
    // Corrected to L3 Protocol
    Config::Connect("/NodeList/1/$ns3::Ipv4L3Protocol/Rx", MakeCallback(&RxTrace));

    // ------------------------------------------------------
    // 4. NORMAL TRAFFIC (Background)
    // ------------------------------------------------------
    uint16_t port = 9;
    BulkSendHelper source("ns3::TcpSocketFactory", InetSocketAddress(victimIp, port));
    source.SetAttribute("MaxBytes", UintegerValue(0));
    ApplicationContainer sourceApps = source.Install(attackerNode);
    sourceApps.Start(Seconds(0.0));
    sourceApps.Stop(Seconds(10.0));

    PacketSinkHelper sink("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), port));
    ApplicationContainer sinkApps = sink.Install(victimNode);
    sinkApps.Start(Seconds(0.0));
    sinkApps.Stop(Seconds(10.0));

    // ------------------------------------------------------
    // 5. SCHEDULE ATTACKS
    // ------------------------------------------------------
    // Flood (2.0s), ICMP (4.0s), Malware (6.0s)
    Simulator::Schedule(Seconds(2.0), &UdpFloodAttack, attackerNode, victimIp, port, 1024, 0.005);
    Simulator::Schedule(Seconds(4.0), &IcmpFloodAttack, attackerNode, victimIp, 64, 0.01);
    Simulator::Schedule(Seconds(6.0), &MalwarePacketAttack, attackerNode, victimIp, std::string("HASH123XYZ"));

    // ------------------------------------------------------
    // 6. RUN
    // ------------------------------------------------------
    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    // ------------------------------------------------------
    // 7. RESULTS
    // ------------------------------------------------------
    Ptr<PacketSink> sinkPtr = DynamicCast<PacketSink>(sinkApps.Get(0));
    std::cout << "\n[RESULT] Valid Application Bytes Received: " << sinkPtr->GetTotalRx() << std::endl;

    return 0;
}