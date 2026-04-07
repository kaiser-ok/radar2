// snmpwalk2snmprec converts snmpwalk text output to numeric snmprec format.
//
// Usage: go run ./cmd/snmpwalk2snmprec -in walk.txt -out device.snmprec
// Or with stdin/stdout: cat walk.txt | go run ./cmd/snmpwalk2snmprec > device.snmprec
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Well-known MIB name → numeric OID prefix mappings.
var mibPrefixes = map[string]string{
	"SNMPv2-MIB::sysDescr":          "1.3.6.1.2.1.1.1",
	"SNMPv2-MIB::sysObjectID":       "1.3.6.1.2.1.1.2",
	"SNMPv2-MIB::sysUpTime":         "1.3.6.1.2.1.1.3",
	"SNMPv2-MIB::sysContact":        "1.3.6.1.2.1.1.4",
	"SNMPv2-MIB::sysName":           "1.3.6.1.2.1.1.5",
	"SNMPv2-MIB::sysLocation":       "1.3.6.1.2.1.1.6",
	"SNMPv2-MIB::sysServices":       "1.3.6.1.2.1.1.7",
	"SNMPv2-MIB::sysORLastChange":   "1.3.6.1.2.1.1.8",
	"SNMPv2-MIB::sysORID":           "1.3.6.1.2.1.1.9.1.2",
	"SNMPv2-MIB::sysORDescr":        "1.3.6.1.2.1.1.9.1.3",
	"SNMPv2-MIB::sysORUpTime":       "1.3.6.1.2.1.1.9.1.4",
	"SNMPv2-MIB::snmpInPkts":        "1.3.6.1.2.1.11.1",
	"SNMPv2-MIB::snmpOutPkts":       "1.3.6.1.2.1.11.2",
	"SNMPv2-MIB::snmpInBadVersions": "1.3.6.1.2.1.11.3",
	"SNMPv2-MIB::snmpInBadCommunityNames":  "1.3.6.1.2.1.11.4",
	"SNMPv2-MIB::snmpInBadCommunityUses":   "1.3.6.1.2.1.11.5",
	"SNMPv2-MIB::snmpInASNParseErrs":       "1.3.6.1.2.1.11.6",
	"SNMPv2-MIB::snmpInTooBigs":            "1.3.6.1.2.1.11.8",
	"SNMPv2-MIB::snmpInNoSuchNames":        "1.3.6.1.2.1.11.9",
	"SNMPv2-MIB::snmpInBadValues":          "1.3.6.1.2.1.11.10",
	"SNMPv2-MIB::snmpInReadOnlys":          "1.3.6.1.2.1.11.11",
	"SNMPv2-MIB::snmpInGenErrs":            "1.3.6.1.2.1.11.12",
	"SNMPv2-MIB::snmpInTotalReqVars":       "1.3.6.1.2.1.11.13",
	"SNMPv2-MIB::snmpInTotalSetVars":       "1.3.6.1.2.1.11.14",
	"SNMPv2-MIB::snmpInGetRequests":        "1.3.6.1.2.1.11.15",
	"SNMPv2-MIB::snmpInGetNexts":           "1.3.6.1.2.1.11.16",
	"SNMPv2-MIB::snmpInSetRequests":        "1.3.6.1.2.1.11.17",
	"SNMPv2-MIB::snmpInGetResponses":       "1.3.6.1.2.1.11.18",
	"SNMPv2-MIB::snmpInTraps":              "1.3.6.1.2.1.11.19",
	"SNMPv2-MIB::snmpOutTooBigs":           "1.3.6.1.2.1.11.20",
	"SNMPv2-MIB::snmpOutNoSuchNames":       "1.3.6.1.2.1.11.21",
	"SNMPv2-MIB::snmpOutBadValues":         "1.3.6.1.2.1.11.22",
	"SNMPv2-MIB::snmpOutGenErrs":           "1.3.6.1.2.1.11.24",
	"SNMPv2-MIB::snmpOutGetRequests":       "1.3.6.1.2.1.11.25",
	"SNMPv2-MIB::snmpOutGetNexts":          "1.3.6.1.2.1.11.26",
	"SNMPv2-MIB::snmpOutSetRequests":       "1.3.6.1.2.1.11.27",
	"SNMPv2-MIB::snmpOutGetResponses":      "1.3.6.1.2.1.11.28",
	"SNMPv2-MIB::snmpOutTraps":             "1.3.6.1.2.1.11.29",
	"SNMPv2-MIB::snmpEnableAuthenTraps":    "1.3.6.1.2.1.11.30",
	"SNMPv2-MIB::snmpSilentDrops":          "1.3.6.1.2.1.11.31",
	"SNMPv2-MIB::snmpProxyDrops":           "1.3.6.1.2.1.11.32",

	"DISMAN-EVENT-MIB::sysUpTimeInstance": "1.3.6.1.2.1.1.3.0",

	// IF-MIB
	"IF-MIB::ifNumber":         "1.3.6.1.2.1.2.1",
	"IF-MIB::ifIndex":          "1.3.6.1.2.1.2.2.1.1",
	"IF-MIB::ifDescr":          "1.3.6.1.2.1.2.2.1.2",
	"IF-MIB::ifType":           "1.3.6.1.2.1.2.2.1.3",
	"IF-MIB::ifMtu":            "1.3.6.1.2.1.2.2.1.4",
	"IF-MIB::ifSpeed":          "1.3.6.1.2.1.2.2.1.5",
	"IF-MIB::ifPhysAddress":    "1.3.6.1.2.1.2.2.1.6",
	"IF-MIB::ifAdminStatus":    "1.3.6.1.2.1.2.2.1.7",
	"IF-MIB::ifOperStatus":     "1.3.6.1.2.1.2.2.1.8",
	"IF-MIB::ifLastChange":     "1.3.6.1.2.1.2.2.1.9",
	"IF-MIB::ifInOctets":       "1.3.6.1.2.1.2.2.1.10",
	"IF-MIB::ifInUcastPkts":    "1.3.6.1.2.1.2.2.1.11",
	"IF-MIB::ifInNUcastPkts":   "1.3.6.1.2.1.2.2.1.12",
	"IF-MIB::ifInDiscards":     "1.3.6.1.2.1.2.2.1.13",
	"IF-MIB::ifInErrors":       "1.3.6.1.2.1.2.2.1.14",
	"IF-MIB::ifInUnknownProtos": "1.3.6.1.2.1.2.2.1.15",
	"IF-MIB::ifOutOctets":      "1.3.6.1.2.1.2.2.1.16",
	"IF-MIB::ifOutUcastPkts":   "1.3.6.1.2.1.2.2.1.17",
	"IF-MIB::ifOutNUcastPkts":  "1.3.6.1.2.1.2.2.1.18",
	"IF-MIB::ifOutDiscards":    "1.3.6.1.2.1.2.2.1.19",
	"IF-MIB::ifOutErrors":      "1.3.6.1.2.1.2.2.1.20",
	"IF-MIB::ifOutQLen":        "1.3.6.1.2.1.2.2.1.21",
	"IF-MIB::ifSpecific":       "1.3.6.1.2.1.2.2.1.22",

	// IF-MIB ifXTable
	"IF-MIB::ifName":                 "1.3.6.1.2.1.31.1.1.1.1",
	"IF-MIB::ifInMulticastPkts":      "1.3.6.1.2.1.31.1.1.1.2",
	"IF-MIB::ifInBroadcastPkts":      "1.3.6.1.2.1.31.1.1.1.3",
	"IF-MIB::ifOutMulticastPkts":     "1.3.6.1.2.1.31.1.1.1.4",
	"IF-MIB::ifOutBroadcastPkts":     "1.3.6.1.2.1.31.1.1.1.5",
	"IF-MIB::ifHCInOctets":           "1.3.6.1.2.1.31.1.1.1.6",
	"IF-MIB::ifHCInUcastPkts":        "1.3.6.1.2.1.31.1.1.1.7",
	"IF-MIB::ifHCInMulticastPkts":    "1.3.6.1.2.1.31.1.1.1.8",
	"IF-MIB::ifHCInBroadcastPkts":    "1.3.6.1.2.1.31.1.1.1.9",
	"IF-MIB::ifHCOutOctets":          "1.3.6.1.2.1.31.1.1.1.10",
	"IF-MIB::ifHCOutUcastPkts":       "1.3.6.1.2.1.31.1.1.1.11",
	"IF-MIB::ifHCOutMulticastPkts":   "1.3.6.1.2.1.31.1.1.1.12",
	"IF-MIB::ifHCOutBroadcastPkts":   "1.3.6.1.2.1.31.1.1.1.13",
	"IF-MIB::ifLinkUpDownTrapEnable": "1.3.6.1.2.1.31.1.1.1.14",
	"IF-MIB::ifHighSpeed":            "1.3.6.1.2.1.31.1.1.1.15",
	"IF-MIB::ifPromiscuousMode":      "1.3.6.1.2.1.31.1.1.1.16",
	"IF-MIB::ifConnectorPresent":     "1.3.6.1.2.1.31.1.1.1.17",
	"IF-MIB::ifAlias":                "1.3.6.1.2.1.31.1.1.1.18",
	"IF-MIB::ifCounterDiscontinuityTime": "1.3.6.1.2.1.31.1.1.1.19",
	"IF-MIB::ifStackHigherLayer":     "1.3.6.1.2.1.31.1.2.1.1",
	"IF-MIB::ifStackLowerLayer":      "1.3.6.1.2.1.31.1.2.1.2",
	"IF-MIB::ifStackStatus":          "1.3.6.1.2.1.31.1.2.1.3",
	"IF-MIB::ifTableLastChange":      "1.3.6.1.2.1.31.1.5",
	"IF-MIB::ifStackLastChange":      "1.3.6.1.2.1.31.1.6",

	// IP-MIB
	"IP-MIB::ipForwarding":        "1.3.6.1.2.1.4.1",
	"IP-MIB::ipDefaultTTL":        "1.3.6.1.2.1.4.2",
	"IP-MIB::ipInReceives":        "1.3.6.1.2.1.4.3",
	"IP-MIB::ipInHdrErrors":       "1.3.6.1.2.1.4.4",
	"IP-MIB::ipInAddrErrors":      "1.3.6.1.2.1.4.5",
	"IP-MIB::ipForwDatagrams":     "1.3.6.1.2.1.4.6",
	"IP-MIB::ipInUnknownProtos":   "1.3.6.1.2.1.4.7",
	"IP-MIB::ipInDiscards":        "1.3.6.1.2.1.4.8",
	"IP-MIB::ipInDelivers":        "1.3.6.1.2.1.4.9",
	"IP-MIB::ipOutRequests":       "1.3.6.1.2.1.4.10",
	"IP-MIB::ipOutDiscards":       "1.3.6.1.2.1.4.11",
	"IP-MIB::ipOutNoRoutes":       "1.3.6.1.2.1.4.12",
	"IP-MIB::ipReasmTimeout":      "1.3.6.1.2.1.4.13",
	"IP-MIB::ipReasmReqds":        "1.3.6.1.2.1.4.14",
	"IP-MIB::ipReasmOKs":          "1.3.6.1.2.1.4.15",
	"IP-MIB::ipReasmFails":        "1.3.6.1.2.1.4.16",
	"IP-MIB::ipFragOKs":           "1.3.6.1.2.1.4.17",
	"IP-MIB::ipFragFails":         "1.3.6.1.2.1.4.18",
	"IP-MIB::ipFragCreates":       "1.3.6.1.2.1.4.19",
	"IP-MIB::ipAdEntAddr":         "1.3.6.1.2.1.4.20.1.1",
	"IP-MIB::ipAdEntIfIndex":      "1.3.6.1.2.1.4.20.1.2",
	"IP-MIB::ipAdEntNetMask":      "1.3.6.1.2.1.4.20.1.3",
	"IP-MIB::ipAdEntBcastAddr":    "1.3.6.1.2.1.4.20.1.4",
	"IP-MIB::ipAdEntReasmMaxSize": "1.3.6.1.2.1.4.20.1.5",
	"IP-MIB::ipNetToMediaIfIndex": "1.3.6.1.2.1.4.22.1.1",
	"IP-MIB::ipNetToMediaPhysAddress": "1.3.6.1.2.1.4.22.1.2",
	"IP-MIB::ipNetToMediaNetAddress":  "1.3.6.1.2.1.4.22.1.3",
	"IP-MIB::ipNetToMediaType":        "1.3.6.1.2.1.4.22.1.4",
	"IP-MIB::ipRoutingDiscards":       "1.3.6.1.2.1.4.23",
	"IP-MIB::icmpInMsgs":              "1.3.6.1.2.1.5.1",
	"IP-MIB::icmpInErrors":            "1.3.6.1.2.1.5.2",
	"IP-MIB::icmpInDestUnreachs":      "1.3.6.1.2.1.5.3",
	"IP-MIB::icmpInTimeExcds":         "1.3.6.1.2.1.5.4",
	"IP-MIB::icmpInParmProbs":         "1.3.6.1.2.1.5.5",
	"IP-MIB::icmpInSrcQuenchs":        "1.3.6.1.2.1.5.6",
	"IP-MIB::icmpInRedirects":         "1.3.6.1.2.1.5.7",
	"IP-MIB::icmpInEchos":             "1.3.6.1.2.1.5.8",
	"IP-MIB::icmpInEchoReps":          "1.3.6.1.2.1.5.9",
	"IP-MIB::icmpInTimestamps":        "1.3.6.1.2.1.5.10",
	"IP-MIB::icmpInTimestampReps":     "1.3.6.1.2.1.5.11",
	"IP-MIB::icmpInAddrMasks":         "1.3.6.1.2.1.5.12",
	"IP-MIB::icmpInAddrMaskReps":      "1.3.6.1.2.1.5.13",
	"IP-MIB::icmpOutMsgs":             "1.3.6.1.2.1.5.14",
	"IP-MIB::icmpOutErrors":           "1.3.6.1.2.1.5.15",
	"IP-MIB::icmpOutDestUnreachs":     "1.3.6.1.2.1.5.16",
	"IP-MIB::icmpOutTimeExcds":        "1.3.6.1.2.1.5.17",
	"IP-MIB::icmpOutParmProbs":        "1.3.6.1.2.1.5.18",
	"IP-MIB::icmpOutSrcQuenchs":       "1.3.6.1.2.1.5.19",
	"IP-MIB::icmpOutRedirects":        "1.3.6.1.2.1.5.20",
	"IP-MIB::icmpOutEchos":            "1.3.6.1.2.1.5.21",
	"IP-MIB::icmpOutEchoReps":         "1.3.6.1.2.1.5.22",
	"IP-MIB::icmpOutTimestamps":       "1.3.6.1.2.1.5.23",
	"IP-MIB::icmpOutTimestampReps":    "1.3.6.1.2.1.5.24",
	"IP-MIB::icmpOutAddrMasks":        "1.3.6.1.2.1.5.25",
	"IP-MIB::icmpOutAddrMaskReps":     "1.3.6.1.2.1.5.26",

	// TCP-MIB
	"TCP-MIB::tcpRtoAlgorithm":  "1.3.6.1.2.1.6.1",
	"TCP-MIB::tcpRtoMin":        "1.3.6.1.2.1.6.2",
	"TCP-MIB::tcpRtoMax":        "1.3.6.1.2.1.6.3",
	"TCP-MIB::tcpMaxConn":       "1.3.6.1.2.1.6.4",
	"TCP-MIB::tcpActiveOpens":   "1.3.6.1.2.1.6.5",
	"TCP-MIB::tcpPassiveOpens":  "1.3.6.1.2.1.6.6",
	"TCP-MIB::tcpAttemptFails":  "1.3.6.1.2.1.6.7",
	"TCP-MIB::tcpEstabResets":   "1.3.6.1.2.1.6.8",
	"TCP-MIB::tcpCurrEstab":     "1.3.6.1.2.1.6.9",
	"TCP-MIB::tcpInSegs":        "1.3.6.1.2.1.6.10",
	"TCP-MIB::tcpOutSegs":       "1.3.6.1.2.1.6.11",
	"TCP-MIB::tcpRetransSegs":   "1.3.6.1.2.1.6.12",
	"TCP-MIB::tcpInErrs":        "1.3.6.1.2.1.6.14",
	"TCP-MIB::tcpOutRsts":       "1.3.6.1.2.1.6.15",
	"TCP-MIB::tcpHCInSegs":      "1.3.6.1.2.1.6.17",
	"TCP-MIB::tcpHCOutSegs":     "1.3.6.1.2.1.6.18",
	"TCP-MIB::tcpConnectionState":      "1.3.6.1.2.1.6.19.1.7",
	"TCP-MIB::tcpConnectionProcess":    "1.3.6.1.2.1.6.19.1.8",
	"TCP-MIB::tcpListenerProcess":      "1.3.6.1.2.1.6.20.1.4",

	// UDP-MIB
	"UDP-MIB::udpInDatagrams":  "1.3.6.1.2.1.7.1",
	"UDP-MIB::udpNoPorts":      "1.3.6.1.2.1.7.2",
	"UDP-MIB::udpInErrors":     "1.3.6.1.2.1.7.3",
	"UDP-MIB::udpOutDatagrams": "1.3.6.1.2.1.7.4",
	"UDP-MIB::udpHCInDatagrams":  "1.3.6.1.2.1.7.8",
	"UDP-MIB::udpHCOutDatagrams": "1.3.6.1.2.1.7.9",

	// BRIDGE-MIB
	"BRIDGE-MIB::dot1dBaseBridgeAddress": "1.3.6.1.2.1.17.1.1",
	"BRIDGE-MIB::dot1dBaseNumPorts":      "1.3.6.1.2.1.17.1.2",
	"BRIDGE-MIB::dot1dBaseType":          "1.3.6.1.2.1.17.1.3",
	"BRIDGE-MIB::dot1dBasePort":          "1.3.6.1.2.1.17.1.4.1.1",
	"BRIDGE-MIB::dot1dBasePortIfIndex":   "1.3.6.1.2.1.17.1.4.1.2",
	"BRIDGE-MIB::dot1dBasePortCircuit":   "1.3.6.1.2.1.17.1.4.1.3",
	"BRIDGE-MIB::dot1dBasePortDelayExceededDiscards": "1.3.6.1.2.1.17.1.4.1.4",
	"BRIDGE-MIB::dot1dBasePortMtuExceededDiscards":   "1.3.6.1.2.1.17.1.4.1.5",
	"BRIDGE-MIB::dot1dStpProtocolSpecification": "1.3.6.1.2.1.17.2.1",
	"BRIDGE-MIB::dot1dStpPriority":              "1.3.6.1.2.1.17.2.2",
	"BRIDGE-MIB::dot1dStpTimeSinceTopologyChange": "1.3.6.1.2.1.17.2.3",
	"BRIDGE-MIB::dot1dStpTopChanges":            "1.3.6.1.2.1.17.2.4",
	"BRIDGE-MIB::dot1dStpDesignatedRoot":        "1.3.6.1.2.1.17.2.5",
	"BRIDGE-MIB::dot1dStpRootCost":              "1.3.6.1.2.1.17.2.6",
	"BRIDGE-MIB::dot1dStpRootPort":              "1.3.6.1.2.1.17.2.7",
	"BRIDGE-MIB::dot1dStpMaxAge":                "1.3.6.1.2.1.17.2.8",
	"BRIDGE-MIB::dot1dStpHelloTime":             "1.3.6.1.2.1.17.2.9",
	"BRIDGE-MIB::dot1dStpHoldTime":              "1.3.6.1.2.1.17.2.10",
	"BRIDGE-MIB::dot1dStpForwardDelay":          "1.3.6.1.2.1.17.2.11",
	"BRIDGE-MIB::dot1dStpBridgeMaxAge":          "1.3.6.1.2.1.17.2.12",
	"BRIDGE-MIB::dot1dStpBridgeHelloTime":       "1.3.6.1.2.1.17.2.13",
	"BRIDGE-MIB::dot1dStpBridgeForwardDelay":    "1.3.6.1.2.1.17.2.14",
	"BRIDGE-MIB::dot1dStpPortPriority":          "1.3.6.1.2.1.17.2.15.1.2",
	"BRIDGE-MIB::dot1dStpPortState":             "1.3.6.1.2.1.17.2.15.1.3",
	"BRIDGE-MIB::dot1dStpPortEnable":            "1.3.6.1.2.1.17.2.15.1.4",
	"BRIDGE-MIB::dot1dStpPortPathCost":          "1.3.6.1.2.1.17.2.15.1.5",
	"BRIDGE-MIB::dot1dStpPortDesignatedRoot":    "1.3.6.1.2.1.17.2.15.1.6",
	"BRIDGE-MIB::dot1dStpPortDesignatedCost":    "1.3.6.1.2.1.17.2.15.1.7",
	"BRIDGE-MIB::dot1dStpPortDesignatedBridge":  "1.3.6.1.2.1.17.2.15.1.8",
	"BRIDGE-MIB::dot1dStpPortDesignatedPort":    "1.3.6.1.2.1.17.2.15.1.9",
	"BRIDGE-MIB::dot1dStpPortForwardTransitions": "1.3.6.1.2.1.17.2.15.1.10",
	"BRIDGE-MIB::dot1dStpPort":                  "1.3.6.1.2.1.17.2.15.1.1",
	"BRIDGE-MIB::dot1dTpAgingTime":              "1.3.6.1.2.1.17.4.2",
	"BRIDGE-MIB::dot1dTpFdbAddress":             "1.3.6.1.2.1.17.4.3.1.1",
	"BRIDGE-MIB::dot1dTpFdbPort":                "1.3.6.1.2.1.17.4.3.1.2",
	"BRIDGE-MIB::dot1dTpFdbStatus":              "1.3.6.1.2.1.17.4.3.1.3",
	"BRIDGE-MIB::dot1dTpPort":                   "1.3.6.1.2.1.17.4.4.1.1",
	"BRIDGE-MIB::dot1dTpPortMaxInfo":            "1.3.6.1.2.1.17.4.4.1.2",
	"BRIDGE-MIB::dot1dTpPortInFrames":           "1.3.6.1.2.1.17.4.4.1.3",
	"BRIDGE-MIB::dot1dTpPortOutFrames":          "1.3.6.1.2.1.17.4.4.1.4",
	"BRIDGE-MIB::dot1dTpPortInDiscards":         "1.3.6.1.2.1.17.4.4.1.5",

	// Q-BRIDGE-MIB
	"Q-BRIDGE-MIB::dot1qVlanVersionNumber":     "1.3.6.1.2.1.17.7.1.1.1",
	"Q-BRIDGE-MIB::dot1qMaxVlanId":             "1.3.6.1.2.1.17.7.1.1.2",
	"Q-BRIDGE-MIB::dot1qMaxSupportedVlans":     "1.3.6.1.2.1.17.7.1.1.3",
	"Q-BRIDGE-MIB::dot1qNumVlans":              "1.3.6.1.2.1.17.7.1.1.4",
	"Q-BRIDGE-MIB::dot1qGvrpStatus":            "1.3.6.1.2.1.17.7.1.1.5",
	"Q-BRIDGE-MIB::dot1qFdbDynamicCount":       "1.3.6.1.2.1.17.7.1.2.1.1.2",
	"Q-BRIDGE-MIB::dot1qTpFdbAddress":          "1.3.6.1.2.1.17.7.1.2.2.1.1",
	"Q-BRIDGE-MIB::dot1qTpFdbPort":             "1.3.6.1.2.1.17.7.1.2.2.1.2",
	"Q-BRIDGE-MIB::dot1qTpFdbStatus":           "1.3.6.1.2.1.17.7.1.2.2.1.3",
	"Q-BRIDGE-MIB::dot1qStaticUnicastAddress":  "1.3.6.1.2.1.17.7.1.3.1.1.1",
	"Q-BRIDGE-MIB::dot1qStaticUnicastReceivePort": "1.3.6.1.2.1.17.7.1.3.1.1.2",
	"Q-BRIDGE-MIB::dot1qStaticUnicastAllowedToGoTo": "1.3.6.1.2.1.17.7.1.3.1.1.3",
	"Q-BRIDGE-MIB::dot1qStaticUnicastStatus":   "1.3.6.1.2.1.17.7.1.3.1.1.4",
	"Q-BRIDGE-MIB::dot1qStaticMulticastAddress": "1.3.6.1.2.1.17.7.1.3.2.1.1",
	"Q-BRIDGE-MIB::dot1qVlanNumDeletes":         "1.3.6.1.2.1.17.7.1.4.1",
	"Q-BRIDGE-MIB::dot1qVlanFdbId":              "1.3.6.1.2.1.17.7.1.4.2.1.3",
	"Q-BRIDGE-MIB::dot1qVlanCurrentEgressPorts": "1.3.6.1.2.1.17.7.1.4.2.1.4",
	"Q-BRIDGE-MIB::dot1qVlanCurrentUntaggedPorts": "1.3.6.1.2.1.17.7.1.4.2.1.5",
	"Q-BRIDGE-MIB::dot1qVlanStatus":             "1.3.6.1.2.1.17.7.1.4.2.1.6",
	"Q-BRIDGE-MIB::dot1qVlanCreationTime":       "1.3.6.1.2.1.17.7.1.4.2.1.7",
	"Q-BRIDGE-MIB::dot1qVlanStaticName":         "1.3.6.1.2.1.17.7.1.4.3.1.1",
	"Q-BRIDGE-MIB::dot1qVlanStaticEgressPorts":  "1.3.6.1.2.1.17.7.1.4.3.1.2",
	"Q-BRIDGE-MIB::dot1qVlanForbiddenEgressPorts": "1.3.6.1.2.1.17.7.1.4.3.1.3",
	"Q-BRIDGE-MIB::dot1qVlanStaticUntaggedPorts": "1.3.6.1.2.1.17.7.1.4.3.1.4",
	"Q-BRIDGE-MIB::dot1qVlanStaticRowStatus":    "1.3.6.1.2.1.17.7.1.4.3.1.5",
	"Q-BRIDGE-MIB::dot1qPvid":                   "1.3.6.1.2.1.17.7.1.4.5.1.1",
	"Q-BRIDGE-MIB::dot1qPortAcceptableFrameTypes": "1.3.6.1.2.1.17.7.1.4.5.1.2",
	"Q-BRIDGE-MIB::dot1qPortIngressFiltering":   "1.3.6.1.2.1.17.7.1.4.5.1.3",
	"Q-BRIDGE-MIB::dot1qPortGvrpStatus":         "1.3.6.1.2.1.17.7.1.4.5.1.4",
	"Q-BRIDGE-MIB::dot1qPortGvrpFailedRegistrations": "1.3.6.1.2.1.17.7.1.4.5.1.5",
	"Q-BRIDGE-MIB::dot1qPortGvrpLastPduOrigin":  "1.3.6.1.2.1.17.7.1.4.5.1.6",

	// POWER-ETHERNET-MIB (RFC 3621)
	"POWER-ETHERNET-MIB::pethPsePortAdminEnable":  "1.3.6.1.2.1.105.1.1.1.3",
	"POWER-ETHERNET-MIB::pethPsePortPowerPairsControlAbility": "1.3.6.1.2.1.105.1.1.1.2",
	"POWER-ETHERNET-MIB::pethPsePortDetectionStatus": "1.3.6.1.2.1.105.1.1.1.6",
	"POWER-ETHERNET-MIB::pethPsePortPowerPriority":   "1.3.6.1.2.1.105.1.1.1.7",
	"POWER-ETHERNET-MIB::pethPsePortMPSAbsentCounter": "1.3.6.1.2.1.105.1.1.1.8",
	"POWER-ETHERNET-MIB::pethPsePortType":             "1.3.6.1.2.1.105.1.1.1.9",
	"POWER-ETHERNET-MIB::pethPsePortPowerClassifications": "1.3.6.1.2.1.105.1.1.1.10",
	"POWER-ETHERNET-MIB::pethMainPseOperStatus":       "1.3.6.1.2.1.105.1.3.1.1.2",
	"POWER-ETHERNET-MIB::pethMainPseConsumptionPower": "1.3.6.1.2.1.105.1.3.1.1.4",
	"POWER-ETHERNET-MIB::pethMainPseUsageThreshold":   "1.3.6.1.2.1.105.1.3.1.1.5",

	// ENTITY-MIB
	"ENTITY-MIB::entPhysicalDescr":        "1.3.6.1.2.1.47.1.1.1.1.2",
	"ENTITY-MIB::entPhysicalVendorType":   "1.3.6.1.2.1.47.1.1.1.1.3",
	"ENTITY-MIB::entPhysicalContainedIn":  "1.3.6.1.2.1.47.1.1.1.1.4",
	"ENTITY-MIB::entPhysicalClass":        "1.3.6.1.2.1.47.1.1.1.1.5",
	"ENTITY-MIB::entPhysicalParentRelPos": "1.3.6.1.2.1.47.1.1.1.1.6",
	"ENTITY-MIB::entPhysicalName":         "1.3.6.1.2.1.47.1.1.1.1.7",
	"ENTITY-MIB::entPhysicalHardwareRev":  "1.3.6.1.2.1.47.1.1.1.1.8",
	"ENTITY-MIB::entPhysicalFirmwareRev":  "1.3.6.1.2.1.47.1.1.1.1.9",
	"ENTITY-MIB::entPhysicalSoftwareRev":  "1.3.6.1.2.1.47.1.1.1.1.10",
	"ENTITY-MIB::entPhysicalSerialNum":    "1.3.6.1.2.1.47.1.1.1.1.11",
	"ENTITY-MIB::entPhysicalMfgName":      "1.3.6.1.2.1.47.1.1.1.1.12",
	"ENTITY-MIB::entPhysicalModelName":    "1.3.6.1.2.1.47.1.1.1.1.13",
	"ENTITY-MIB::entPhysicalAlias":        "1.3.6.1.2.1.47.1.1.1.1.14",
	"ENTITY-MIB::entPhysicalAssetID":      "1.3.6.1.2.1.47.1.1.1.1.15",
	"ENTITY-MIB::entPhysicalIsFRU":        "1.3.6.1.2.1.47.1.1.1.1.16",

	// CISCO-PROCESS-MIB (CPU)
	"CISCO-PROCESS-MIB::cpmCPUTotal5secRev": "1.3.6.1.4.1.9.9.109.1.1.1.1.6",
	"CISCO-PROCESS-MIB::cpmCPUTotal1minRev": "1.3.6.1.4.1.9.9.109.1.1.1.1.7",
	"CISCO-PROCESS-MIB::cpmCPUTotal5minRev": "1.3.6.1.4.1.9.9.109.1.1.1.1.8",

	// CISCO-ENVMON-MIB
	"CISCO-ENVMON-MIB::ciscoEnvMonTemperatureStatusDescr":  "1.3.6.1.4.1.9.9.13.1.3.1.2",
	"CISCO-ENVMON-MIB::ciscoEnvMonTemperatureStatusValue":  "1.3.6.1.4.1.9.9.13.1.3.1.3",
	"CISCO-ENVMON-MIB::ciscoEnvMonTemperatureThreshold":    "1.3.6.1.4.1.9.9.13.1.3.1.4",
	"CISCO-ENVMON-MIB::ciscoEnvMonTemperatureLastShutdown": "1.3.6.1.4.1.9.9.13.1.3.1.5",
	"CISCO-ENVMON-MIB::ciscoEnvMonTemperatureState":        "1.3.6.1.4.1.9.9.13.1.3.1.6",
	"CISCO-ENVMON-MIB::ciscoEnvMonFanStatusDescr":          "1.3.6.1.4.1.9.9.13.1.4.1.2",
	"CISCO-ENVMON-MIB::ciscoEnvMonFanState":                "1.3.6.1.4.1.9.9.13.1.4.1.3",
	"CISCO-ENVMON-MIB::ciscoEnvMonSupplyStatusDescr":       "1.3.6.1.4.1.9.9.13.1.5.1.2",
	"CISCO-ENVMON-MIB::ciscoEnvMonSupplyState":             "1.3.6.1.4.1.9.9.13.1.5.1.3",
	"CISCO-ENVMON-MIB::ciscoEnvMonSupplySource":            "1.3.6.1.4.1.9.9.13.1.5.1.4",

	// CISCO-STACK-MIB (old CPU)
	"CISCO-PROCESS-MIB::cpmCPUTotal5sec": "1.3.6.1.4.1.9.9.109.1.1.1.1.3",
	"CISCO-PROCESS-MIB::cpmCPUTotal1min": "1.3.6.1.4.1.9.9.109.1.1.1.1.4",
	"CISCO-PROCESS-MIB::cpmCPUTotal5min": "1.3.6.1.4.1.9.9.109.1.1.1.1.5",

	// CISCO-VTP-MIB
	"CISCO-VTP-MIB::vtpVlanState":   "1.3.6.1.4.1.9.9.46.1.3.1.1.2",
	"CISCO-VTP-MIB::vtpVlanType":    "1.3.6.1.4.1.9.9.46.1.3.1.1.3",
	"CISCO-VTP-MIB::vtpVlanName":    "1.3.6.1.4.1.9.9.46.1.3.1.1.4",
	"CISCO-VTP-MIB::vtpVlanMtu":     "1.3.6.1.4.1.9.9.46.1.3.1.1.5",
	"CISCO-VTP-MIB::vtpVlanDot10Said": "1.3.6.1.4.1.9.9.46.1.3.1.1.6",
	"CISCO-VTP-MIB::vlanTrunkPortVlansEnabled": "1.3.6.1.4.1.9.9.46.1.6.1.1.4",

	// CISCO-CDP-MIB
	"CISCO-CDP-MIB::cdpCacheDeviceId":   "1.3.6.1.4.1.9.9.23.1.2.1.1.6",
	"CISCO-CDP-MIB::cdpCacheDevicePort": "1.3.6.1.4.1.9.9.23.1.2.1.1.7",
	"CISCO-CDP-MIB::cdpCachePlatform":   "1.3.6.1.4.1.9.9.23.1.2.1.1.8",

	// LLDP-MIB
	"LLDP-MIB::lldpRemChassisId":     "1.0.8802.1.1.2.1.4.1.1.5",
	"LLDP-MIB::lldpRemPortId":        "1.0.8802.1.1.2.1.4.1.1.7",
	"LLDP-MIB::lldpRemPortDesc":      "1.0.8802.1.1.2.1.4.1.1.8",
	"LLDP-MIB::lldpRemSysName":       "1.0.8802.1.1.2.1.4.1.1.9",
	"LLDP-MIB::lldpRemSysDesc":       "1.0.8802.1.1.2.1.4.1.1.10",
	"LLDP-MIB::lldpRemSysCapSupported": "1.0.8802.1.1.2.1.4.1.1.11",
	"LLDP-MIB::lldpRemSysCapEnabled": "1.0.8802.1.1.2.1.4.1.1.12",
	"LLDP-MIB::lldpRemManAddrIfSubtype": "1.0.8802.1.1.2.1.4.2.1.3",
	"LLDP-MIB::lldpRemManAddrIfId":   "1.0.8802.1.1.2.1.4.2.1.4",
	"LLDP-MIB::lldpRemManAddrOID":    "1.0.8802.1.1.2.1.4.2.1.5",

	// MIKROTIK-MIB
	"MIKROTIK-MIB::mtxrHlCpuLoad":              "1.3.6.1.4.1.14988.1.1.3.14",
	"MIKROTIK-MIB::mtxrHlTemperature":           "1.3.6.1.4.1.14988.1.1.3.10",
	"MIKROTIK-MIB::mtxrHlActiveFan":             "1.3.6.1.4.1.14988.1.1.3.9",
	"MIKROTIK-MIB::mtxrHlVoltage":               "1.3.6.1.4.1.14988.1.1.3.8",
	"MIKROTIK-MIB::mtxrHlCurrent":               "1.3.6.1.4.1.14988.1.1.3.7",
	"MIKROTIK-MIB::mtxrHlPower":                 "1.3.6.1.4.1.14988.1.1.3.12",
	"MIKROTIK-MIB::mtxrHlProcessorTemperature":  "1.3.6.1.4.1.14988.1.1.3.11",
	"MIKROTIK-MIB::mtxrHlTotalMemory":           "1.3.6.1.4.1.14988.1.1.3.5",
	"MIKROTIK-MIB::mtxrHlFreeMemory":            "1.3.6.1.4.1.14988.1.1.3.6",
	"MIKROTIK-MIB::mtxrHlTotalHdd":              "1.3.6.1.4.1.14988.1.1.3.3",
	"MIKROTIK-MIB::mtxrHlFreeHdd":               "1.3.6.1.4.1.14988.1.1.3.4",
	"MIKROTIK-MIB::mtxrHlFirmwareVersion":       "1.3.6.1.4.1.14988.1.1.3.1",
	"MIKROTIK-MIB::mtxrHlBoardName":             "1.3.6.1.4.1.14988.1.1.3.18",
	"MIKROTIK-MIB::mtxrHlSerialNumber":          "1.3.6.1.4.1.14988.1.1.3.19",
	"MIKROTIK-MIB::mtxrHlFirmwareUpgradeVersion": "1.3.6.1.4.1.14988.1.1.3.2",
	"MIKROTIK-MIB::mtxrPOEInterfaceIndex":       "1.3.6.1.4.1.14988.1.1.15.1.1.1",
	"MIKROTIK-MIB::mtxrPOEName":                 "1.3.6.1.4.1.14988.1.1.15.1.1.2",
	"MIKROTIK-MIB::mtxrPOEStatus":               "1.3.6.1.4.1.14988.1.1.15.1.1.3",
	"MIKROTIK-MIB::mtxrPOECurrent":              "1.3.6.1.4.1.14988.1.1.15.1.1.4",
	"MIKROTIK-MIB::mtxrPOEVoltage":              "1.3.6.1.4.1.14988.1.1.15.1.1.5",
	"MIKROTIK-MIB::mtxrPOEPower":                "1.3.6.1.4.1.14988.1.1.15.1.1.6",

	// SNMPv2-SMI (for OID references in walk output)
	"SNMPv2-SMI::enterprises": "1.3.6.1.4.1",
	"SNMPv2-SMI::mib-2":      "1.3.6.1.2.1",
	"SNMPv2-SMI::zeroDotZero": "0.0",

	// HOST-RESOURCES-MIB
	"HOST-RESOURCES-MIB::hrSystemUptime":        "1.3.6.1.2.1.25.1.1",
	"HOST-RESOURCES-MIB::hrSystemDate":          "1.3.6.1.2.1.25.1.2",
	"HOST-RESOURCES-MIB::hrSystemProcesses":     "1.3.6.1.2.1.25.1.6",
	"HOST-RESOURCES-MIB::hrSystemMaxProcesses":  "1.3.6.1.2.1.25.1.7",
	"HOST-RESOURCES-MIB::hrMemorySize":          "1.3.6.1.2.1.25.2.2",
	"HOST-RESOURCES-MIB::hrStorageIndex":        "1.3.6.1.2.1.25.2.3.1.1",
	"HOST-RESOURCES-MIB::hrStorageType":         "1.3.6.1.2.1.25.2.3.1.2",
	"HOST-RESOURCES-MIB::hrStorageDescr":        "1.3.6.1.2.1.25.2.3.1.3",
	"HOST-RESOURCES-MIB::hrStorageAllocationUnits": "1.3.6.1.2.1.25.2.3.1.4",
	"HOST-RESOURCES-MIB::hrStorageSize":         "1.3.6.1.2.1.25.2.3.1.5",
	"HOST-RESOURCES-MIB::hrStorageUsed":         "1.3.6.1.2.1.25.2.3.1.6",
	"HOST-RESOURCES-MIB::hrProcessorFrwID":      "1.3.6.1.2.1.25.3.3.1.1",
	"HOST-RESOURCES-MIB::hrProcessorLoad":       "1.3.6.1.2.1.25.3.3.1.2",

	// CISCO-MEMORY-POOL-MIB
	"CISCO-MEMORY-POOL-MIB::ciscoMemoryPoolName":       "1.3.6.1.4.1.9.9.48.1.1.1.2",
	"CISCO-MEMORY-POOL-MIB::ciscoMemoryPoolAlternate":  "1.3.6.1.4.1.9.9.48.1.1.1.3",
	"CISCO-MEMORY-POOL-MIB::ciscoMemoryPoolValid":      "1.3.6.1.4.1.9.9.48.1.1.1.4",
	"CISCO-MEMORY-POOL-MIB::ciscoMemoryPoolUsed":       "1.3.6.1.4.1.9.9.48.1.1.1.5",
	"CISCO-MEMORY-POOL-MIB::ciscoMemoryPoolFree":       "1.3.6.1.4.1.9.9.48.1.1.1.6",
	"CISCO-MEMORY-POOL-MIB::ciscoMemoryPoolLargestFree": "1.3.6.1.4.1.9.9.48.1.1.1.7",

	// CISCO-FLASH-MIB
	"CISCO-FLASH-MIB::ciscoFlashDeviceSize":    "1.3.6.1.4.1.9.9.10.1.1.4.1.1.5",

	// CISCO-IMAGE-MIB
	"CISCO-IMAGE-MIB::ciscoImageString": "1.3.6.1.4.1.9.9.25.1.1.1.2",

	// EtherLike-MIB
	"EtherLike-MIB::dot3StatsAlignmentErrors":         "1.3.6.1.2.1.10.7.2.1.2",
	"EtherLike-MIB::dot3StatsFCSErrors":               "1.3.6.1.2.1.10.7.2.1.3",
	"EtherLike-MIB::dot3StatsSingleCollisionFrames":   "1.3.6.1.2.1.10.7.2.1.4",
	"EtherLike-MIB::dot3StatsMultipleCollisionFrames": "1.3.6.1.2.1.10.7.2.1.5",
	"EtherLike-MIB::dot3StatsDeferredTransmissions":   "1.3.6.1.2.1.10.7.2.1.7",
	"EtherLike-MIB::dot3StatsLateCollisions":          "1.3.6.1.2.1.10.7.2.1.8",
	"EtherLike-MIB::dot3StatsExcessiveCollisions":     "1.3.6.1.2.1.10.7.2.1.9",
	"EtherLike-MIB::dot3StatsCarrierSenseErrors":      "1.3.6.1.2.1.10.7.2.1.11",
	"EtherLike-MIB::dot3StatsFrameTooLongs":           "1.3.6.1.2.1.10.7.2.1.13",
	"EtherLike-MIB::dot3StatsDuplexStatus":            "1.3.6.1.2.1.10.7.2.1.19",

	// SNMPv2-MIB (continued)
	"SNMPv2-MIB::snmpSetSerialNo": "1.3.6.1.6.3.1.1.6.1",

	// IP-MIB (extended stats)
	"IP-MIB::ipAddressSpinLock":                    "1.3.6.1.2.1.4.33",
	"IP-MIB::ipSystemStatsInReceives":              "1.3.6.1.2.1.4.31.1.1.3",
	"IP-MIB::ipSystemStatsHCInReceives":            "1.3.6.1.2.1.4.31.1.1.4",
	"IP-MIB::ipSystemStatsInOctets":                "1.3.6.1.2.1.4.31.1.1.5",
	"IP-MIB::ipSystemStatsHCInOctets":              "1.3.6.1.2.1.4.31.1.1.6",
	"IP-MIB::ipSystemStatsInHdrErrors":             "1.3.6.1.2.1.4.31.1.1.7",
	"IP-MIB::ipSystemStatsInNoRoutes":              "1.3.6.1.2.1.4.31.1.1.8",
	"IP-MIB::ipSystemStatsInAddrErrors":            "1.3.6.1.2.1.4.31.1.1.9",
	"IP-MIB::ipSystemStatsInUnknownProtos":         "1.3.6.1.2.1.4.31.1.1.10",
	"IP-MIB::ipSystemStatsInTruncatedPkts":         "1.3.6.1.2.1.4.31.1.1.11",
	"IP-MIB::ipSystemStatsInForwDatagrams":         "1.3.6.1.2.1.4.31.1.1.12",
	"IP-MIB::ipSystemStatsHCInForwDatagrams":       "1.3.6.1.2.1.4.31.1.1.13",
	"IP-MIB::ipSystemStatsReasmReqds":              "1.3.6.1.2.1.4.31.1.1.14",
	"IP-MIB::ipSystemStatsReasmOKs":                "1.3.6.1.2.1.4.31.1.1.15",
	"IP-MIB::ipSystemStatsReasmFails":              "1.3.6.1.2.1.4.31.1.1.16",
	"IP-MIB::ipSystemStatsInDiscards":              "1.3.6.1.2.1.4.31.1.1.17",
	"IP-MIB::ipSystemStatsInDelivers":              "1.3.6.1.2.1.4.31.1.1.18",
	"IP-MIB::ipSystemStatsHCInDelivers":            "1.3.6.1.2.1.4.31.1.1.19",
	"IP-MIB::ipSystemStatsOutRequests":             "1.3.6.1.2.1.4.31.1.1.20",
	"IP-MIB::ipSystemStatsHCOutRequests":           "1.3.6.1.2.1.4.31.1.1.21",
	"IP-MIB::ipSystemStatsOutNoRoutes":             "1.3.6.1.2.1.4.31.1.1.22",
	"IP-MIB::ipSystemStatsOutForwDatagrams":        "1.3.6.1.2.1.4.31.1.1.23",
	"IP-MIB::ipSystemStatsHCOutForwDatagrams":      "1.3.6.1.2.1.4.31.1.1.24",
	"IP-MIB::ipSystemStatsOutDiscards":             "1.3.6.1.2.1.4.31.1.1.25",
	"IP-MIB::ipSystemStatsOutFragReqds":            "1.3.6.1.2.1.4.31.1.1.26",
	"IP-MIB::ipSystemStatsOutFragOKs":              "1.3.6.1.2.1.4.31.1.1.27",
	"IP-MIB::ipSystemStatsOutFragFails":            "1.3.6.1.2.1.4.31.1.1.28",
	"IP-MIB::ipSystemStatsOutFragCreates":          "1.3.6.1.2.1.4.31.1.1.29",
	"IP-MIB::ipSystemStatsOutTransmits":            "1.3.6.1.2.1.4.31.1.1.30",
	"IP-MIB::ipSystemStatsHCOutTransmits":          "1.3.6.1.2.1.4.31.1.1.31",
	"IP-MIB::ipSystemStatsOutOctets":               "1.3.6.1.2.1.4.31.1.1.32",
	"IP-MIB::ipSystemStatsHCOutOctets":             "1.3.6.1.2.1.4.31.1.1.33",
	"IP-MIB::ipSystemStatsInMcastPkts":             "1.3.6.1.2.1.4.31.1.1.34",
	"IP-MIB::ipSystemStatsHCInMcastPkts":           "1.3.6.1.2.1.4.31.1.1.35",
	"IP-MIB::ipSystemStatsInMcastOctets":           "1.3.6.1.2.1.4.31.1.1.36",
	"IP-MIB::ipSystemStatsHCInMcastOctets":         "1.3.6.1.2.1.4.31.1.1.37",
	"IP-MIB::ipSystemStatsOutMcastPkts":            "1.3.6.1.2.1.4.31.1.1.38",
	"IP-MIB::ipSystemStatsHCOutMcastPkts":          "1.3.6.1.2.1.4.31.1.1.39",
	"IP-MIB::ipSystemStatsOutMcastOctets":          "1.3.6.1.2.1.4.31.1.1.40",
	"IP-MIB::ipSystemStatsHCOutMcastOctets":        "1.3.6.1.2.1.4.31.1.1.41",
	"IP-MIB::ipSystemStatsInBcastPkts":             "1.3.6.1.2.1.4.31.1.1.42",
	"IP-MIB::ipSystemStatsHCInBcastPkts":           "1.3.6.1.2.1.4.31.1.1.43",
	"IP-MIB::ipSystemStatsOutBcastPkts":            "1.3.6.1.2.1.4.31.1.1.44",
	"IP-MIB::ipSystemStatsHCOutBcastPkts":          "1.3.6.1.2.1.4.31.1.1.45",
	"IP-MIB::ipSystemStatsDiscontinuityTime":       "1.3.6.1.2.1.4.31.1.1.46",
	"IP-MIB::ipSystemStatsRefreshRate":             "1.3.6.1.2.1.4.31.1.1.47",
	"IP-MIB::icmpStatsInMsgs":                      "1.3.6.1.2.1.5.29.1.1",
	"IP-MIB::icmpStatsInErrors":                    "1.3.6.1.2.1.5.29.1.2",
	"IP-MIB::icmpStatsOutMsgs":                     "1.3.6.1.2.1.5.29.1.3",
	"IP-MIB::icmpStatsOutErrors":                   "1.3.6.1.2.1.5.29.1.4",

	// UDP-MIB (extended)
	"UDP-MIB::udpLocalAddress":      "1.3.6.1.2.1.7.5.1.1",
	"UDP-MIB::udpLocalPort":         "1.3.6.1.2.1.7.5.1.2",
	"UDP-MIB::udpEndpointProcess":   "1.3.6.1.2.1.7.7.1.8",

	// EtherLike-MIB (extended)
	"EtherLike-MIB::dot3StatsIndex":                      "1.3.6.1.2.1.10.7.2.1.1",
	"EtherLike-MIB::dot3StatsInternalMacTransmitErrors":  "1.3.6.1.2.1.10.7.2.1.10",
	"EtherLike-MIB::dot3StatsInternalMacReceiveErrors":   "1.3.6.1.2.1.10.7.2.1.16",
	"EtherLike-MIB::dot3StatsEtherChipSet":               "1.3.6.1.2.1.10.7.2.1.17",
	"EtherLike-MIB::dot3StatsSymbolErrors":               "1.3.6.1.2.1.10.7.2.1.18",
	"EtherLike-MIB::dot3StatsSQETestErrors":              "1.3.6.1.2.1.10.7.2.1.6",

	// HOST-RESOURCES-MIB (extended)
	"HOST-RESOURCES-MIB::hrDeviceIndex":              "1.3.6.1.2.1.25.3.2.1.1",
	"HOST-RESOURCES-MIB::hrDeviceType":               "1.3.6.1.2.1.25.3.2.1.2",
	"HOST-RESOURCES-MIB::hrDeviceDescr":              "1.3.6.1.2.1.25.3.2.1.3",
	"HOST-RESOURCES-MIB::hrDeviceID":                 "1.3.6.1.2.1.25.3.2.1.4",
	"HOST-RESOURCES-MIB::hrDeviceStatus":             "1.3.6.1.2.1.25.3.2.1.5",
	"HOST-RESOURCES-MIB::hrDeviceErrors":             "1.3.6.1.2.1.25.3.2.1.6",
	"HOST-RESOURCES-MIB::hrStorageAllocationFailures": "1.3.6.1.2.1.25.2.3.1.7",


	// IP-MIB icmpMsgStats
	"IP-MIB::icmpMsgStatsInPkts":  "1.3.6.1.2.1.5.30.1.3",
	"IP-MIB::icmpMsgStatsOutPkts": "1.3.6.1.2.1.5.31.1.3",

	// IF-MIB (additional)
	"IF-MIB::ifRcvAddressStatus": "1.3.6.1.2.1.31.1.4.1.2",
	"IF-MIB::ifRcvAddressType":   "1.3.6.1.2.1.31.1.4.1.3",

	// NOTIFICATION-LOG-MIB
	"NOTIFICATION-LOG-MIB::nlmConfigGlobalEntryLimit":          "1.3.6.1.2.1.92.1.1.1",
	"NOTIFICATION-LOG-MIB::nlmConfigGlobalAgeOut":              "1.3.6.1.2.1.92.1.1.2",
	"NOTIFICATION-LOG-MIB::nlmStatsGlobalNotificationsLogged":  "1.3.6.1.2.1.92.1.2.1",
	"NOTIFICATION-LOG-MIB::nlmStatsGlobalNotificationsBumped": "1.3.6.1.2.1.92.1.2.2",

	// RMON-MIB (etherStats)
	"RMON-MIB::rmon": "1.3.6.1.2.1.16",

	// IP-FORWARD-MIB
	"IP-FORWARD-MIB::ipCidrRouteNumber":    "1.3.6.1.2.1.4.24.3",
	"IP-FORWARD-MIB::ipCidrRouteDest":      "1.3.6.1.2.1.4.24.4.1.1",
	"IP-FORWARD-MIB::ipCidrRouteMask":      "1.3.6.1.2.1.4.24.4.1.2",
	"IP-FORWARD-MIB::ipCidrRouteTos":       "1.3.6.1.2.1.4.24.4.1.3",
	"IP-FORWARD-MIB::ipCidrRouteNextHop":   "1.3.6.1.2.1.4.24.4.1.4",
	"IP-FORWARD-MIB::ipCidrRouteIfIndex":   "1.3.6.1.2.1.4.24.4.1.5",
	"IP-FORWARD-MIB::ipCidrRouteType":      "1.3.6.1.2.1.4.24.4.1.6",
	"IP-FORWARD-MIB::ipCidrRouteProto":     "1.3.6.1.2.1.4.24.4.1.7",
	"IP-FORWARD-MIB::ipCidrRouteAge":       "1.3.6.1.2.1.4.24.4.1.8",
	"IP-FORWARD-MIB::ipCidrRouteInfo":      "1.3.6.1.2.1.4.24.4.1.9",
	"IP-FORWARD-MIB::ipCidrRouteNextHopAS": "1.3.6.1.2.1.4.24.4.1.10",
	"IP-FORWARD-MIB::ipCidrRouteMetric1":   "1.3.6.1.2.1.4.24.4.1.11",
	"IP-FORWARD-MIB::ipCidrRouteMetric2":   "1.3.6.1.2.1.4.24.4.1.12",
	"IP-FORWARD-MIB::ipCidrRouteMetric3":   "1.3.6.1.2.1.4.24.4.1.13",
	"IP-FORWARD-MIB::ipCidrRouteMetric4":   "1.3.6.1.2.1.4.24.4.1.14",
	"IP-FORWARD-MIB::ipCidrRouteMetric5":   "1.3.6.1.2.1.4.24.4.1.15",
	"IP-FORWARD-MIB::ipCidrRouteStatus":    "1.3.6.1.2.1.4.24.4.1.16",

	// IPV6-MIB
	"IPV6-MIB::ipv6Interfaces":         "1.3.6.1.2.1.55.1.1",
	"IPV6-MIB::ipv6IfDescr":            "1.3.6.1.2.1.55.1.5.1.2",
	"IPV6-MIB::ipv6IfLowerLayer":       "1.3.6.1.2.1.55.1.5.1.3",
	"IPV6-MIB::ipv6IfEffectiveMtu":     "1.3.6.1.2.1.55.1.5.1.4",
	"IPV6-MIB::ipv6IfReasmMaxSize":     "1.3.6.1.2.1.55.1.5.1.5",
	"IPV6-MIB::ipv6IfIdentifier":       "1.3.6.1.2.1.55.1.5.1.6",
	"IPV6-MIB::ipv6IfIdentifierLength": "1.3.6.1.2.1.55.1.5.1.7",
	"IPV6-MIB::ipv6IfPhysicalAddress":  "1.3.6.1.2.1.55.1.5.1.8",
	"IPV6-MIB::ipv6IfAdminStatus":      "1.3.6.1.2.1.55.1.5.1.9",
	"IPV6-MIB::ipv6IfOperStatus":       "1.3.6.1.2.1.55.1.5.1.10",
	"IPV6-MIB::ipv6IfLastChange":       "1.3.6.1.2.1.55.1.5.1.11",
	"IPV6-MIB::ipv6AddrPfxLength":      "1.3.6.1.2.1.55.1.8.1.2",
	"IPV6-MIB::ipv6AddrType":           "1.3.6.1.2.1.55.1.8.1.3",
	"IPV6-MIB::ipv6AddrAnycastFlag":    "1.3.6.1.2.1.55.1.8.1.4",
	"IPV6-MIB::ipv6AddrStatus":         "1.3.6.1.2.1.55.1.8.1.5",
	"IPV6-MIB::ipv6RouteNumber":        "1.3.6.1.2.1.55.1.11.1",
	"IPV6-MIB::ipv6RouteIfIndex":       "1.3.6.1.2.1.55.1.12.1.4",
	"IPV6-MIB::ipv6RouteNextHop":       "1.3.6.1.2.1.55.1.12.1.5",
	"IPV6-MIB::ipv6RouteType":          "1.3.6.1.2.1.55.1.12.1.6",
	"IPV6-MIB::ipv6RouteProtocol":      "1.3.6.1.2.1.55.1.12.1.7",
	"IPV6-MIB::ipv6RoutePolicy":        "1.3.6.1.2.1.55.1.12.1.8",
	"IPV6-MIB::ipv6RouteAge":           "1.3.6.1.2.1.55.1.12.1.9",
	"IPV6-MIB::ipv6RouteNextHopRDI":    "1.3.6.1.2.1.55.1.12.1.10",
	"IPV6-MIB::ipv6RouteMetric":        "1.3.6.1.2.1.55.1.12.1.11",
	"IPV6-MIB::ipv6RouteWeight":        "1.3.6.1.2.1.55.1.12.1.12",
	"IPV6-MIB::ipv6RouteInfo":          "1.3.6.1.2.1.55.1.12.1.13",
	"IPV6-MIB::ipv6RouteValid":         "1.3.6.1.2.1.55.1.12.1.14",
}

// Reverse lookup: find the longest matching MIB prefix for a name like "IF-MIB::ifDescr.5"
func resolveOID(name string) (string, bool) {
	// Already numeric?
	if isNumericOID(name) {
		return name, true
	}

	// Try exact match first (for scalar OIDs with .0)
	// Split "MIB::object.index" into "MIB::object" + ".index"
	for mibName, oid := range mibPrefixes {
		if strings.HasPrefix(name, mibName) {
			suffix := name[len(mibName):]
			return oid + suffix, true
		}
	}

	return "", false
}

func isNumericOID(s string) bool {
	s = strings.TrimPrefix(s, ".")
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// Parse snmpwalk value types
var (
	reString    = regexp.MustCompile(`^STRING:\s*"?(.*?)"?$`)
	reInteger   = regexp.MustCompile(`^INTEGER:\s*(.+)$`)
	reOID       = regexp.MustCompile(`^OID:\s*(.+)$`)
	reCounter32 = regexp.MustCompile(`^Counter32:\s*(\d+)$`)
	reCounter64 = regexp.MustCompile(`^Counter64:\s*(\d+)$`)
	reGauge32   = regexp.MustCompile(`^Gauge32:\s*(\d+)$`)
	reTicks     = regexp.MustCompile(`^Timeticks:\s*\((\d+)\)`)
	reHexStr    = regexp.MustCompile(`^Hex-STRING:\s*(.+)$`)
	reIpAddr    = regexp.MustCompile(`^IpAddress:\s*(.+)$`)
	reOpaque    = regexp.MustCompile(`^Opaque:\s*(.+)$`)
	reBits      = regexp.MustCompile(`^BITS:\s*(.+)$`)
	reNetAddr   = regexp.MustCompile(`^Network Address:\s*(.+)$`)
	reNoSuch    = regexp.MustCompile(`^No Such (Object|Instance)`)
	reEndOfMib  = regexp.MustCompile(`^End of MIB`)
	reIntEnum   = regexp.MustCompile(`^INTEGER:\s*\w+\((\d+)\)$`)
)

type snmprecLine struct {
	oid      string
	typeCode string
	value    string
}

func parseWalkLine(line string) (*snmprecLine, error) {
	// Split on " = " to get OID name and value
	parts := strings.SplitN(line, " = ", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("no ' = ' separator")
	}

	oidName := strings.TrimSpace(parts[0])
	valueStr := strings.TrimSpace(parts[1])

	// Resolve the OID name to numeric
	numOID, ok := resolveOID(oidName)
	if !ok {
		return nil, fmt.Errorf("unknown OID: %s", oidName)
	}
	numOID = strings.TrimPrefix(numOID, ".")

	// Skip no-such / end-of-mib
	if reNoSuch.MatchString(valueStr) || reEndOfMib.MatchString(valueStr) {
		return nil, fmt.Errorf("skip: %s", valueStr)
	}

	// Empty string
	if valueStr == `STRING:` || valueStr == `STRING: ""` || valueStr == `STRING: ` {
		return &snmprecLine{oid: numOID, typeCode: "4", value: ""}, nil
	}

	// INTEGER with enum like "INTEGER: up(1)"
	if m := reIntEnum.FindStringSubmatch(valueStr); m != nil {
		return &snmprecLine{oid: numOID, typeCode: "2", value: m[1]}, nil
	}

	// STRING
	if m := reString.FindStringSubmatch(valueStr); m != nil {
		return &snmprecLine{oid: numOID, typeCode: "4", value: m[1]}, nil
	}

	// INTEGER
	if m := reInteger.FindStringSubmatch(valueStr); m != nil {
		val := m[1]
		// Could be just a number or a named value
		val = strings.TrimSpace(val)
		if n, err := strconv.Atoi(val); err == nil {
			return &snmprecLine{oid: numOID, typeCode: "2", value: strconv.Itoa(n)}, nil
		}
		// Fallback: treat as 0 for unknown enum names
		return &snmprecLine{oid: numOID, typeCode: "2", value: "0"}, nil
	}

	// OID
	if m := reOID.FindStringSubmatch(valueStr); m != nil {
		resolved, ok := resolveOID(strings.TrimSpace(m[1]))
		if !ok {
			resolved = m[1]
		}
		resolved = strings.TrimPrefix(resolved, ".")
		return &snmprecLine{oid: numOID, typeCode: "6", value: resolved}, nil
	}

	// Counter32
	if m := reCounter32.FindStringSubmatch(valueStr); m != nil {
		return &snmprecLine{oid: numOID, typeCode: "41", value: m[1]}, nil
	}

	// Counter64
	if m := reCounter64.FindStringSubmatch(valueStr); m != nil {
		return &snmprecLine{oid: numOID, typeCode: "46", value: m[1]}, nil
	}

	// Gauge32
	if m := reGauge32.FindStringSubmatch(valueStr); m != nil {
		return &snmprecLine{oid: numOID, typeCode: "42", value: m[1]}, nil
	}

	// Timeticks
	if m := reTicks.FindStringSubmatch(valueStr); m != nil {
		return &snmprecLine{oid: numOID, typeCode: "43", value: m[1]}, nil
	}

	// Hex-STRING → hex-encoded octet string
	if m := reHexStr.FindStringSubmatch(valueStr); m != nil {
		hexVal := strings.ReplaceAll(strings.TrimSpace(m[1]), " ", "")
		hexVal = strings.ReplaceAll(hexVal, "\n", "")
		return &snmprecLine{oid: numOID, typeCode: "4x", value: hexVal}, nil
	}

	// IpAddress
	if m := reIpAddr.FindStringSubmatch(valueStr); m != nil {
		return &snmprecLine{oid: numOID, typeCode: "64", value: strings.TrimSpace(m[1])}, nil
	}

	// Opaque (treat as hex-encoded octet string)
	if m := reOpaque.FindStringSubmatch(valueStr); m != nil {
		return &snmprecLine{oid: numOID, typeCode: "4", value: strings.TrimSpace(m[1])}, nil
	}

	// BITS
	if m := reBits.FindStringSubmatch(valueStr); m != nil {
		hexVal := strings.ReplaceAll(strings.TrimSpace(m[1]), " ", "")
		return &snmprecLine{oid: numOID, typeCode: "4x", value: hexVal}, nil
	}

	// Network Address
	if m := reNetAddr.FindStringSubmatch(valueStr); m != nil {
		return &snmprecLine{oid: numOID, typeCode: "64", value: strings.TrimSpace(m[1])}, nil
	}

	// Fallback: octet string
	return &snmprecLine{oid: numOID, typeCode: "4", value: valueStr}, nil
}

func main() {
	inFile := flag.String("in", "", "Input snmpwalk file (default: stdin)")
	outFile := flag.String("out", "", "Output snmprec file (default: stdout)")
	flag.Parse()

	var reader io.Reader = os.Stdin
	if *inFile != "" {
		f, err := os.Open(*inFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening input: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		reader = f
	}

	var writer io.Writer = os.Stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		writer = f
	}

	scanner := bufio.NewScanner(reader)
	// Handle long lines (some SNMP walks have very long hex strings)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	var converted, skipped, errors int
	var pendingLine string

	flush := func() {
		if pendingLine == "" {
			return
		}
		rec, err := parseWalkLine(pendingLine)
		if err != nil {
			skipped++
		} else {
			fmt.Fprintf(writer, "%s|%s|%s\n", rec.oid, rec.typeCode, rec.value)
			converted++
		}
		pendingLine = ""
	}

	for scanner.Scan() {
		line := scanner.Text()

		// Continuation lines (multi-line string values, hex dumps) don't have " = "
		if !strings.Contains(line, " = ") && pendingLine != "" {
			// Append to pending line (hex continuation or multi-line string)
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				pendingLine += " " + trimmed
			}
			continue
		}

		// Flush previous line
		flush()
		pendingLine = line
	}
	// Flush last line
	flush()

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		errors++
	}

	fmt.Fprintf(os.Stderr, "Converted: %d, Skipped: %d, Errors: %d\n", converted, skipped, errors)
}
