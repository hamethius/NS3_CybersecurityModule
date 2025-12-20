#include "ns3/ns3cybermod.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/core-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ScenarioSpoofing");

int main(int argc, char *argv[])
{
    SimParams params;
    params.numAttackers = 2;
    params.numVictims   = 5;
    params.attackPort   = 9000;
    params.attackType   = "ip-spoofing"; 
    params.attackMode   = "ddos";

    NS_LOG_UNCOND("--- SCENARIO: IP IDENTITY THEFT ---");
    NS_LOG_UNCOND("Goal: Attackers impersonate other nodes in the network.");

    // Standard Setup
    params.attackers.Create(params.numAttackers);
    params.victims.Create(params.numVictims);

    NodeContainer allNodes;
    allNodes.Add(params.attackers);
    allNodes.Add(params.victims);

    InternetStackHelper internet;
    internet.Install(allNodes);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
    csma.SetChannelAttribute("Delay", StringValue("1ms"));
    NetDeviceContainer devices = csma.Install(allNodes);

    Ipv4AddressHelper ip;
    ip.SetBase("172.16.0.0", "255.255.255.0");
    params.iface.push_back(ip.Assign(devices));

    SetupAttack(params);

    Simulator::Stop(Seconds(5.0));
    Simulator::Run();
    
    SaveLogs(params);
    Simulator::Destroy();
    return 0;
}
