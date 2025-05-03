package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/subcommands"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type icmpCmd struct {
	ipv6 bool
}

func (*icmpCmd) Name() string     { return "icmp" }
func (*icmpCmd) Synopsis() string { return "test connectivity by icmp" }
func (*icmpCmd) Usage() string {
	return `arp [-6] <target host>:
        test connectivity by icmp

`
}

func (c *icmpCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&c.ipv6, "6", false, "use ipv6")
}

func (c *icmpCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	var nw string
	var listen string
	var proto string
	if c.ipv6 {
		nw = "ip6"
		proto = "ip6:ipv6-icmp"
		listen = "::"
	} else {
		nw = "ip4"
		proto = "ip4:icmp"
		listen = "0.0.0.0"
	}

	dstIp, err := net.ResolveIPAddr(nw, f.Arg(0))
	if err != nil {
		fmt.Printf("failed to resolve host %v: %v\n", f.Arg(0), err)
		return subcommands.ExitFailure
	}

	if dstIp.String() != f.Arg(0) {
		fmt.Printf("resolved target host: %s (%s)\n", dstIp.String(), f.Arg(0))
	}

	conn, err := icmp.ListenPacket(proto, listen)
	if err != nil {
		fmt.Println("failed to listen packet:", err)
		return subcommands.ExitFailure
	}
	defer conn.Close()

	start, err := writeIcmp(conn, dstIp.IP)
	if err != nil {
		fmt.Println("failed to write packet:", err)
		return subcommands.ExitFailure
	}
	peer, finish, err := readIcmp(conn, dstIp.IP)
	if err != nil {
		fmt.Println("failed to read packet:", err)
		return subcommands.ExitFailure
	}

	duration := float64(finish.UnixMicro()-start.UnixMicro()) / 1000
	fmt.Printf("reply at %v (time= %.3f ms)\n", peer.String(), duration)

	return subcommands.ExitSuccess
}

func writeIcmp(c *icmp.PacketConn, ip net.IP) (*time.Time, error) {
	var icmpType icmp.Type
	if isIPv6(ip) {
		icmpType = ipv6.ICMPTypeEchoRequest
	} else {
		icmpType = ipv4.ICMPTypeEcho
	}
	msg := icmp.Message{
		Type: icmpType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte(""),
		},
	}

	b, err := msg.Marshal(nil)
	if err != nil {
		return nil, err
	}

	err = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if _, err := c.WriteTo(b, &net.IPAddr{IP: ip}); err != nil {
		return nil, err
	}

	return &now, nil
}

func readIcmp(c *icmp.PacketConn, ip net.IP) (net.Addr, *time.Time, error) {
	var proto int
	if isIPv6(ip) {
		proto = ipv6.ICMPTypeEchoRequest.Protocol()
	} else {
		proto = ipv4.ICMPTypeEcho.Protocol()
	}
	reply := make([]byte, 1500)
	err := c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		return nil, nil, err
	}

	n, peer, err := c.ReadFrom(reply)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()

	rm, err := icmp.ParseMessage(proto, reply[:n])
	if err != nil {
		return nil, nil, err
	}
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		return peer, &now, nil
	case ipv6.ICMPTypeEchoReply:
		return peer, &now, nil
	default:
		return nil, nil, fmt.Errorf("got %+v from %v; want echo reply", rm, peer)
	}
}
