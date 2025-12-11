/*
 * NS-3 Network Attacks & Defense Module
 * This program simulates:
 *   - Attacks: UDP Flood, ICMP Flood, Malware Injection
 *   - Defenses: Firewall, Rate Limiting, Port Filtering, Malware Detection (DPI)
 *
 * The goal is to show how an attacker sends harmful packets
 * and how the defender filters and drops them.
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
#include <iomanip>
#include <string>
#include <map>

using namespace ns3;

/* ===========================================================================
 *                          SIMULATION CONFIG FLAGS
 * These are ON/OFF switches to enable or disable attacks or defenses.
 * Useful for testing each part individually.
 * ===========================================================================*/

bool g_simEnableFirewall    = true;   // Turn entire firewall on/off
bool g_simEnableRateLimit   = true;   // Turn UDP flood rate limit defense on/off
bool g_simEnablePortFilter  = true;   // Block packets with suspicious ports
bool g_simEnableDpi         = true;   // Deep Packet Inspection (malware detection)

bool g_simRunUdpFlood       = true;   // Enable UDP flood attack
bool g_simRunIcmpFlood      = true;   // Enable ICMP flood attack
bool g_simRunMalware        = true;   // Enable malware injection attack
bool g_simSummaryMode       = false;  // Make logs shorter to avoid spam

/* ===========================================================================
 *                                 LOGGING SYSTEM
 * This prints packet information in colored format.
 * It also supports "summary mode" which hides repeated logs.
 * ===========================================================================*/

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_PURPLE  "\033[1;35m"

// Store how many similar logs appear each second
std::map<std::string, int> g_logCounts;
int g_currentSecond = -1;

// Helper to extract node number from NS-3 context string
std::string GetNodeIdFromContext(std::string context) {
    size_t first = context.find("/NodeList/");
    if (first != std::string::npos) {
        size_t second = context.find("/", first + 10);
        return "Node " + context.substr(first + 10, second - (first + 10));
    }
    return "Unknown";
}

/* 
 * This function prints what the firewall decides:
 * - PASS or DROP
 * - the reason (malware, flood, etc.)
 * - the packet's source IP and protocol
 */
void LogPacketDecision(std::string context, Ipv4Address src, std::string proto,
                       std::string action, std::string reason, std::string color) {

    // Show at most 3 similar messages per second
    int timeSec = (int)Simulator::Now().GetSeconds();
    if (timeSec > g_currentSecond) {
        g_currentSecond = timeSec;
        g_logCounts.clear();
    }

    std::string key = src.ToString() + action + reason;

    if (g_simSummaryMode) {
        if (g_logCounts[key] >= 3) return; // skip repeated log
        g_logCounts[key]++;
    }

    // Print formatted log row
    std::cout << std::left
              << "[" << std::setw(7) << Simulator::Now().GetSeconds() << "s]"
              << " | " << std::setw(8) << GetNodeIdFromContext(context)
              << " | " << std::setw(13) << src
              << " | " << std::setw(5) << proto
              << " | " << color << std::setw(8) << action << COLOR_RESET
              << " | " << reason << std::endl;

    if (g_simSummaryMode && g_logCounts[key] == 3) {
        std::cout << "           | ... (Hiding similar logs this second) ..." << std::endl;
    }
}

/* ===========================================================================
 *                           DEFENSE MODULE (FIREWALL)
 * This is the actual firewall that runs on the victim node.
 *
 * It performs:
 *   - Deep Packet Inspection (detect malware)
 *   - Port filtering (blocks port 0 fake ICMP)
 *   - Rate limiting (limits UDP flood)
 * ===========================================================================*/

class DefenseModule : public Object {
public:
    static TypeId GetTypeId(void);

    DefenseModule() {
        m_packetCount = 0;
        m_lastCheckTime = Seconds(0);
        m_threshold = 50; // max UDP packets per second allowed
    }

    /*
     * This function is called for every packet arriving at the victim.
     * It decides whether to PASS or DROP the packet.
     */
    bool InspectPacket(std::string context, Ptr<const Packet> packet, Ptr<Ipv4> ipv4, uint32_t interface) {

        // If firewall is turned off → everything passes
        if (!g_simEnableFirewall) {
            Ipv4Header ipHeader; packet->PeekHeader(ipHeader);
            LogPacketDecision(context, ipHeader.GetSource(), "ALL", "PASS", "Firewall disabled", COLOR_GREEN);
            return true;
        }

        Ipv4Header ipHeader;
        packet->PeekHeader(ipHeader);

        Ipv4Address srcIp = ipHeader.GetSource();
        uint32_t packetSize = packet->GetSize();

        // Identify protocol (TCP/UDP/ICMP)
        std::string protoStr = "OTHER";
        if (ipHeader.GetProtocol() == 6) protoStr = "TCP";
        else if (ipHeader.GetProtocol() == 17) protoStr = "UDP";
        else if (ipHeader.GetProtocol() == 1) protoStr = "ICMP";

        bool isUdp = (ipHeader.GetProtocol() == 17);

        /* ---------------------- 1. MALWARE CHECK (DPI) ---------------------- */
        if (g_simEnableDpi) {
            uint8_t *data = new uint8_t[packetSize];
            packet->CopyData(data, packetSize);
            std::string payload((char*)data, packetSize);
            delete[] data;

            // If malware signature text is found → drop
            if (payload.find("MALWARE_HASH") != std::string::npos) {
                LogPacketDecision(context, srcIp, protoStr, "DROP", "Malware detected", COLOR_PURPLE);
                return false;
            }
        }

        /* ---------------------- 2. PORT FILTER ------------------------------ */
        if (g_simEnablePortFilter && isUdp) {
            UdpHeader udp;
            Ptr<Packet> copy = packet->Copy();
            copy->RemoveHeader(ipHeader);  // remove IP header
            if (copy->PeekHeader(udp)) {
                if (udp.GetDestinationPort() == 0) { // Port 0 = fake ICMP flood
                    LogPacketDecision(context, srcIp, protoStr, "DROP", "Blocked port 0", COLOR_YELLOW);
                    return false;
                }
            }
        }

        /* ---------------------- 3. RATE LIMITING ---------------------------- */
        if (g_simEnableRateLimit && isUdp) {
            Time now = Simulator::Now();
            // Reset counter every second
            if (now - m_lastCheckTime >= Seconds(1)) {
                m_packetCount = 0;
                m_lastCheckTime = now;
            }

            m_packetCount++;

            // If too many packets arrive → drop flood packets
            if (m_packetCount > m_threshold) {
                LogPacketDecision(context, srcIp, protoStr, "DROP", "UDP Flood detected", COLOR_RED);
                return false;
            }
        }

        // If no defense blocked it → allow the packet
        LogPacketDecision(context, srcIp, protoStr, "PASS", "Packet allowed", COLOR_GREEN);
        return true;
    }

private:
    uint32_t m_packetCount;   // counts packets per second
    Time m_lastCheckTime;
    uint32_t m_threshold;     // max allowed packets per second
};

// Register module with NS-3
NS_OBJECT_ENSURE_REGISTERED(DefenseModule);

TypeId DefenseModule::GetTypeId(void) {
    static TypeId tid = TypeId("DefenseModule")
        .SetParent<Object>()
        .SetGroupName("Network")
        .AddConstructor<DefenseModule>();
    return tid;
}

// Global firewall pointer
Ptr<DefenseModule> g_firewall;

/*
 * This function is connected to the NS-3 Rx trace.
 * Every time a packet arrives, we forward it to the firewall.
 */
void RxTrace(std::string context, Ptr<const Packet> packet, Ptr<Ipv4> ipv4, uint32_t interface) {
    if (g_firewall) g_firewall->InspectPacket(context, packet, ipv4, interface);
}

/* ===========================================================================
 *                                ATTACK FUNCTIONS
 * These simulate the attacker sending harmful packets.
 * ===========================================================================*/

// Helper that repeatedly sends UDP packets for flood
void SendFloodPacket(Ptr<Socket> socket, InetSocketAddress remote, uint32_t size, double interval) {
    if (!g_simRunUdpFlood) return;
    Ptr<Packet> packet = Create<Packet>(size);
    socket->SendTo(packet, 0, remote);
    Simulator::Schedule(Seconds(interval), &SendFloodPacket, socket, remote, size, interval);
}

/* -------------------------- 1. UDP FLOOD ATTACK --------------------------- */
void UdpFloodAttack(Ptr<Node> attacker, Ipv4Address victim, uint16_t port, uint32_t size, double interval) {
    if (!g_simRunUdpFlood) return;
    std::cout << COLOR_RED << "\n>>> UDP Flood Attack Started\n" << COLOR_RESET;
    Ptr<Socket> socket = Socket::CreateSocket(attacker, UdpSocketFactory::GetTypeId());
    InetSocketAddress remote(victim, port);
    Simulator::Schedule(Seconds(0), &SendFloodPacket, socket, remote, size, interval);
}

/* -------------------------- 2. ICMP FLOOD ATTACK -------------------------- */
void IcmpFloodAttack(Ptr<Node> attacker, Ipv4Address victim, uint32_t size, double interval) {
    if (!g_simRunIcmpFlood) return;
    std::cout << COLOR_YELLOW << "\n>>> ICMP Flood Attack Started\n" << COLOR_RESET;

    // Simulated using UDP port 0 (invalid port)
    Ptr<Socket> socket = Socket::CreateSocket(attacker, UdpSocketFactory::GetTypeId());
    InetSocketAddress remote(victim, 0);

    Simulator::Schedule(Seconds(0.01), [socket, remote, size, interval]() {
        Ptr<Packet> packet = Create<Packet>(size);
        socket->SendTo(packet, 0, remote);

        Simulator::Schedule(Seconds(interval), [socket, remote, size, interval]() {
            Ptr<Packet> packet = Create<Packet>(size);
            socket->SendTo(packet, 0, remote);
        });
    });
}

/* -------------------------- 3. MALWARE ATTACK ----------------------------- */
void MalwarePacketAttack(Ptr<Node> attacker, Ipv4Address victim, std::string hash) {
    if (!g_simRunMalware) return;
    std::cout << COLOR_PURPLE << "\n>>> Malware Injection Started\n" << COLOR_RESET;

    Ptr<Socket> socket = Socket::CreateSocket(attacker, UdpSocketFactory::GetTypeId());
    InetSocketAddress remote(victim, 5555);

    std::string payload = "MALWARE_HASH:" + hash;
    Ptr<Packet> packet = Create<Packet>((uint8_t*)payload.c_str(), payload.size());

    Simulator::Schedule(Seconds(1.0), [socket, remote, packet]() {
        socket->SendTo(packet, 0, remote);
    });
}

/* ===========================================================================
 *                                   MAIN
 * This builds the network, sets up attacker + victim, and schedules attacks.
 * ===========================================================================*/

int main(int argc, char* argv[]) {

    // Allow turning ON/OFF features from command line
    CommandLine cmd;
    cmd.AddValue("firewall", "Enable Firewall", g_simEnableFirewall);
    cmd.AddValue("summary", "Enable Summary Log Mode", g_simSummaryMode);
    cmd.Parse(argc, argv);

    /* ---------------------- PRINT CONFIG TABLE ---------------------------- */
    std::cout << "\n================ CYBERSECURITY SIMULATION CONFIG ================\n";
    std::cout << "Firewall:            " << (g_simEnableFirewall ? "ON" : "OFF") << std::endl;
    std::cout << "Rate Limiting:       " << (g_simEnableRateLimit ? "ON" : "OFF") << std::endl;
    std::cout << "Port Filtering:      " << (g_simEnablePortFilter ? "ON" : "OFF") << std::endl;
    std::cout << "Malware DPI:         " << (g_simEnableDpi ? "ON" : "OFF") << std::endl;
    std::cout << "==================================================================\n\n";

    /* ---------------------- CREATE TWO NODES ----------------------------- */
    NodeContainer nodes;
    nodes.Create(2);  // Node 0 = attacker, Node 1 = victim

    /* ---------------------- CREATE NETWORK CHANNEL ----------------------- */
    PointToPointHelper ptp;
    ptp.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    ptp.SetChannelAttribute("Delay", StringValue("2ms"));
    NetDeviceContainer devices = ptp.Install(nodes);

    /* ---------------------- INSTALL INTERNET ----------------------------- */
    InternetStackHelper internet;
    internet.Install(nodes);

    // Assign IP addresses
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer iface = ipv4.Assign(devices);

    Ptr<Node> attackerNode = nodes.Get(0);
    Ptr<Node> victimNode = nodes.Get(1);
    Ipv4Address victimIp = iface.GetAddress(1);

    /* ---------------------- INSTALL FIREWALL ----------------------------- */
    g_firewall = CreateObject<DefenseModule>();
    // Attach firewall to Rx event of victim
    Config::Connect("/NodeList/1/$ns3::Ipv4L3Protocol/Rx", MakeCallback(&RxTrace));

    /* ---------------------- NORMAL LEGIT TRAFFIC ------------------------- */
    uint16_t port = 9;

    // Attacker sends normal TCP traffic also
    BulkSendHelper source("ns3::TcpSocketFactory", InetSocketAddress(victimIp, port));
    source.SetAttribute("MaxBytes", UintegerValue(0));
    ApplicationContainer sourceApps = source.Install(attackerNode);
    sourceApps.Start(Seconds(0));
    sourceApps.Stop(Seconds(10));

    // Victim receives normal traffic
    PacketSinkHelper sink("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), port));
    ApplicationContainer sinkApps = sink.Install(victimNode);
    sinkApps.Start(Seconds(0));
    sinkApps.Stop(Seconds(10));

    /* ---------------------- SCHEDULE ATTACKS ----------------------------- */
    Simulator::Schedule(Seconds(2), &UdpFloodAttack, attackerNode, victimIp, port, 1024, 0.005);
    Simulator::Schedule(Seconds(4), &IcmpFloodAttack, attackerNode, victimIp, 64, 0.01);
    Simulator::Schedule(Seconds(6), &MalwarePacketAttack, attackerNode, victimIp, "HASH123XYZ");

    /* ---------------------- RUN SIMULATION ------------------------------- */
    Simulator::Stop(Seconds(10));
    Simulator::Run();
    Simulator::Destroy();

    // Print number of legitimate bytes received
    Ptr<PacketSink> sinkPtr = DynamicCast<PacketSink>(sinkApps.Get(0));
    std::cout << "\n================== SIMULATION COMPLETE ==================\n";
    std::cout << "Total Valid Bytes Received: " << sinkPtr->GetTotalRx() << std::endl;
    std::cout << "==========================================================\n";

    return 0;
}
