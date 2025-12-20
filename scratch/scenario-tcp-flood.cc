#include "ns3/ns3cybermod.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/core-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ScenarioTcpFlood");

int main(int argc, char *argv[])
{
    SimParams params;
    params.numAttackers = 3;
    params.numVictims   = 2;
    params.attackPort   = 80;          // Web Server Port
    params.attackRate   = "1Mbps";     // Lower rate, but TCP overhead is high
    params.attackType   = "tcp-flood"; 
    params.attackMode   = "dos";       // Simpler DoS

    NS_LOG_UNCOND("--- SCENARIO: TCP SERVICE EXHAUSTION ---");
    NS_LOG_UNCOND("Goal: Overwhelm Port 80 on web servers.");

    // Standard Setup
    params.attackers.Create(params.numAttackers);
    params.victims.Create(params.numVictims);

    NodeContainer allNodes;
    allNodes.Add(params.attackers);
    allNodes.Add(params.victims);

    InternetStackHelper internet;
    internet.Install(allNodes);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("50Mbps"));
    csma.SetChannelAttribute("Delay", StringValue("5ms"));
    NetDeviceContainer devices = csma.Install(allNodes);

    Ipv4AddressHelper ip;
    ip.SetBase("10.0.0.0", "255.255.255.0");
    params.iface.push_back(ip.Assign(devices));

    SetupAttack(params);

    Simulator::Stop(Seconds(8.0));
    Simulator::Run();
    
    SaveLogs(params);
    Simulator::Destroy();
    return 0;
}
