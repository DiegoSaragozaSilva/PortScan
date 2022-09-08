from DebugUtils import *
import sys
import re
import socket
import os
from tabulate import tabulate
import ipaddress

defaultSocketTimeout = 1
defaultPortRange = "0-65535"

validArgFlags = {
    "--host=": "Target IP to perform the scan. Must follow the 4 octets standard.",
    "--port-range=": "Port range. Must follow the standard 'n-m' where n < m.",
    "--cidr=": "CIDR block to perform the network scan. Must follow the 4 octets and mask standard.",
    "-h": "This command."
}

def logHelp():
    debugLog(LogType.INFO, "PortScan usage: python3 PortScan.py [flag]=[value] ...")
    flagData = [[data[0].replace('=', ''), data[1]] for data in validArgFlags.items()]
    print(tabulate(flagData, headers = ["Flag", "Info"]))

def isHostAvailable(targetIP):
    # Return a ping connection result to host
    return True if os.system(f"ping -c 3 {targetIP} >/dev/null 2>&1") == 0 else False 

def scanHost(targetIP, portRange):
    debugLog(LogType.INFO, f"Checking host {targetIP} availability...")
    if not isHostAvailable(targetIP):
        debugLog(LogType.WARNING, f"Host {targetIP} not available. No ports will be scanned.")
        return
    debugLog(LogType.INFO, "Host is available. Performing scan...")
    ports = []
    for port in portRange:
        portSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        portSocket.settimeout(defaultSocketTimeout)
        try:
            if portSocket.connect_ex((targetIP, port)) == 0:
                ports.append([port, socket.getservbyport(port, "tcp"), "tcp", "opened"])
        except:
            pass
        portSocket.settimeout(None)
        portSocket.close()
    return ports

def scanNetwork(CIDR, portRange):
    hostPortStatus = [];
    possibleHosts = [str(ip) for ip in ipaddress.IPv4Network(CIDR)]
    for targetIP in possibleHosts:
        debugLog(LogType.INFO, f"Checking host {targetIP} availability...")
        if not isHostAvailable(targetIP):
            debugLog(LogType.WARNING, f"Host {targetIP} not available. No ports will be scanned.")
            continue
        debugLog(LogType.INFO, "Host is available. Performing scan...")
        ports = []
        for port in portRange:
            portSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            portSocket.settimeout(defaultSocketTimeout)
            try: 
                if portSocket.connect_ex((targetIP, port)) == 0:
                    ports.append([targetIP + ":" + str(port), socket.getservbyport(port, "tcp"), "tcp", "opened"])
            except:
                pass
            portSocket.settimeout(None)
            portSocket.close()
        hostPortStatus.append(ports)
    return hostPortStatus

if __name__ == "__main__":
    # Read args
    # 1 - Target IP, if none, scan network
    # 2 - Port range, if none, scan all well-known-ports 
    # 3 - CIDR, if Target IP none, use it
    allArgs = sys.argv[1:]

    # Argument gattering
    targetIP = None
    portRange = None
    cidr = None
    for arg in allArgs:
        flagFound = False
        for flag in validArgFlags.keys():
            cleanArg = arg.split('=', 1)[0]
            if flag.find(cleanArg) == 0:
                flagFound = True
                flagIndex = list(validArgFlags.keys()).index(flag)
                # IP port
                if flagIndex == 0:
                    targetIP = arg.replace(flag, '')
                    break
                # Port range
                elif flagIndex == 1:
                    portRange = arg.replace(flag, '')
                    break
                # CIDR block
                elif flagIndex == 2:
                    cidr = arg.replace(flag, '')
                    break
                # Help command
                elif flagIndex == 3:
                    logHelp()
                    exit()
        if not flagFound:
            debugLog(LogType.ERROR, f"Invalid argument '{arg}' at position {allArgs.index(arg)}.")
            raise Exception(ExceptionType.INVALID_ARGUMENT)

    # Argument validation
    ipPattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    portPattern = re.compile("[0-9]+-[0-9]+")
    cidrPattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")

    if not targetIP == None:
        if not re.search(ipPattern, targetIP):
            debugLog(LogType.ERROR, f"Invalid target IP. The presented IP does not follow the 4 octets standard pattern.")
            raise Exception(ExceptionType.INVALID_PATTERN)                
    
    if not portRange == None:
        if not re.search(portPattern, portRange):
            debugLog(LogType.ERROR, f"Invalid port range. The presented doest not follow the pattern 'n-m'.")
            raise Exception(ExceptionType.INVALID_PATTERN)
    
    if not cidr == None:
        if not re.search(cidrPattern, cidr):
            debugLog(LogType.ERROR, f"Invalid CIDR block. The presented CIDR block does not follow the 4 octets and mask standard pattern.")
            raise Exception(ExceptionType.INVALID_PATTERN)                

    # Default port range
    if portRange == None:
        debugLog(LogType.INFO, f"No port range selected. Using default {defaultPortRange} well-known-port range.")
        portRange = defaultPortRange

    portRangeLimits = portRange.split('-')
    portRange = [i for i in range(int(portRangeLimits[0]), int(portRangeLimits[1]) + 1)]

    if targetIP == None:
        if cidr == None:
            debugLog(LogType.ERROR, "No CIDR block selected. It is needed for network scan.")
            raise Exception(ExceptionType.MISSING_ARGUMENT)

        debugLog(LogType.INFO, "No host selected. Scan will be performed through all available hosts at the network using the CIDR block.")
        
        debugLog(LogType.INFO, f"Scanning port range {portRange[0]}-{portRange[len(portRange) - 1]} from all hosts...")
        hostPortStatus = scanNetwork(cidr, portRange)
        debugLog(LogType.SUCCESS, f"Scanning completed!")
    
        debugLog(LogType.INFO, f"Logging the results:")
        for portStatus in hostPortStatus:
            if len(portStatus) > 0:
                print(tabulate(portStatus, headers=["Port number", "Service", "Protocol", "Status"]), '\n')
    else:
        debugLog(LogType.INFO, f"Scanning port range {portRange[0]}-{portRange[len(portRange) - 1]} from host {targetIP}...")
        portStatus = scanHost(targetIP, portRange)
        debugLog(LogType.SUCCESS, f"Scanning completed!")
    
        debugLog(LogType.INFO, f"Logging the results:")
        print(tabulate(portStatus, headers=["Port number", "Service", "Protocol", "Status"]))
