package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/subcommands"
)

type tcpCmd struct {
	ipv6 bool
}

func (*tcpCmd) Name() string     { return "tcp" }
func (*tcpCmd) Synopsis() string { return "test connectivity by tcp" }
func (*tcpCmd) Usage() string {
	return `arp [-6] <target host> <target port>:
        test connectivity by tcp

`
}

func (c *tcpCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&c.ipv6, "6", false, "use ipv6")
}

func (c *tcpCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	var nw string
	if c.ipv6 {
		nw = "ip6"
	} else {
		nw = "ip4"
	}

	dstIp, err := net.ResolveIPAddr(nw, f.Arg(0))
	if err != nil {
		fmt.Printf("failed to resolve host %v: %v\n", f.Arg(0), err)
		return subcommands.ExitFailure
	}

	port, err := strconv.Atoi(f.Arg(1))
	if err != nil {
		fmt.Printf("failed to get port %v: %v\n", f.Arg(1), err)
		return subcommands.ExitFailure
	}

	if dstIp.String() != f.Arg(0) {
		fmt.Printf("resolved target host: %s (%s)\n", dstIp.String(), f.Arg(0))
	}

	var target string
	if c.ipv6 {
		target = fmt.Sprintf("[%s]:%v", dstIp.String(), port)
	} else {
		target = fmt.Sprintf("%s:%v", dstIp.String(), port)
	}

	start := time.Now()
	conn, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Println("failed to connect:", err)
		return subcommands.ExitFailure
	}
	defer conn.Close()

	finish := time.Now()
	duration := float64(finish.UnixMicro()-start.UnixMicro()) / 1000

	fmt.Printf("connect at %v (time= %.3f ms)\n", target, duration)

	return subcommands.ExitSuccess
}
