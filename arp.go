package main

import (
	"bytes"
	"context"
	"flag"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/subcommands"
)

type arpCmd struct {
	ifaceName string
}

func (*arpCmd) Name() string     { return "arp" }
func (*arpCmd) Synopsis() string { return "test connectivity by arp" }
func (*arpCmd) Usage() string {
	return `arp [-i string] <target ip>:
        test connectivity by arp

`
}

func (c *arpCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.ifaceName, "i", "", "source interface name")
}

func (c *arpCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	log.SetPrefix("[arp] ")

	dstIp, err := parseIP(f.Arg(0))
	if err != nil {
		log.Println("failed to parse target ip address:", err)
		return subcommands.ExitUsageError
	}
	log.Println("target ip address:", dstIp)

	log.Println("iface name", c.ifaceName)

	iface, err := getInterface(c.ifaceName)
	if err != nil {
		log.Println("failed to get default interface:", err)
		return subcommands.ExitUsageError
	}
	log.Println("source interface:", iface.Name)
	log.Println("source hw address:", iface.HardwareAddr)

	srcIp, err := getInterfaceIPv4(iface)
	if err != nil {
		log.Println("failed to get interface ip address:", err)
		return subcommands.ExitUsageError
	}
	log.Println("source ip address:", srcIp)

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Println("failed to open pcap handle:", err)
		return subcommands.ExitFailure
	}
	defer handle.Close()

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go readARP(handle, iface, stop)

	// Write our scan packets out to the handle.
	log.Println("write arp request packet")
	if err := writeARP(handle, iface, srcIp, dstIp); err != nil {
		log.Printf("error writing packets on %v: %v", iface.Name, err)
		return subcommands.ExitSuccess
	}

	// Wait for finish
	<-stop

	return subcommands.ExitSuccess
}

func readARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
				continue
			}

			log.Println("read arp response packet")
			log.Printf("ip %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
			close(stop)
		}
	}
}

func writeARP(handle *pcap.Handle, iface *net.Interface, srcIp *net.IP, dstIp net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcIp.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIp.To4()),
	}

	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Send ARP request.
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	return nil
}
