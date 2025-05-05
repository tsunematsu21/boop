package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"time"

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
	dstIp, err := parseIP(f.Arg(0))
	if err != nil {
		fmt.Println("failed to parse target ip address:", err)
		return subcommands.ExitUsageError
	}

	iface, err := getInterface(c.ifaceName)
	if err != nil {
		fmt.Println("failed to get default interface:", err)
		return subcommands.ExitUsageError
	}

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("failed to open pcap handle:", err)
		return subcommands.ExitFailure
	}
	defer handle.Close()

	start := time.Now()
	if err := writeArpPacket(handle, iface, dstIp); err != nil {
		fmt.Printf("error writing packets on %v: %v\n", iface.Name, err)
		return subcommands.ExitFailure
	}

	arp := readArpPacket(handle, iface)
	duration := float64(time.Since(start).Microseconds()) / 1000
	if arp != nil {
		fmt.Printf("ip %v is at %v (if=%s time=%.3f ms)\n", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress), iface.Name, duration)
	}

	return subcommands.ExitSuccess
}

func writeArpPacket(handle *pcap.Handle, iface *net.Interface, dstIp net.IP) error {
	srcIp, err := getInterfaceIPv4(iface)
	if err != nil {
		return err
	}

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

func readArpPacket(handle *pcap.Handle, iface *net.Interface) *layers.ARP {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		packet := <-in
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}
		arp := arpLayer.(*layers.ARP)
		if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
			continue
		}
		return arp
	}
}
