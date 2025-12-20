#include "ns3/ns3cybermod.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/core-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ScenarioUdpFlood");

int main(int argc, char *argv[])
{
    // 1. Initialize from your Header
    SimParams params;
    params.numAttackers = 10;          // Heavy DDoS
    params.numVictims   = 1;           // Single Target
    params.attackPort   = 5000;
    params.attackRate   = "50Mbps";    // High Bandwidth
    params.attackType   = "udp-flood"; 
    params.attackMode   = "ddos";

    NS_LOG_UNCOND("--- SCENARIO: MASSIVE UDP FLOOD ---");
    NS_LOG_UNCOND("Goal: Saturate bandwidth of a single victim.");

    // 2. Standard NS-3 Setup (Nodes, Internet, CSMA)
    params.attackers.Create(params.numAttackers);
    params.victims.Create(params.numVictims);

    NodeContainer allNodes;
    allNodes.Add(params.attackers);
    allNodes.Add(params.victims);

    InternetStackHelper internet;
    internet.Install(allNodes);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
    csma.SetChannelAttribute("Delay", StringValue("2ms"));
    NetDeviceContainer devices = csma.Install(allNodes);

    Ipv4AddressHelper ip;
    ip.SetBase("192.168.1.0", "255.255.255.0");
    params.iface.push_back(ip.Assign(devices));

    // 3. Trigger the Module Logic
    SetupAttack(params);

    // 4. Run
    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    
    SaveLogs(params);
    Simulator::Destroy();
    return 0;
}

