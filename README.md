# boop
The connectivity test tool made with Golang.

Supported protocols:
* ARP
* ICMP (echo request/reply)
* TCP

## Usage
```
$ go build ./...
$ ./boop help
Usage: boop <flags> <subcommand> <subcommand args>

Subcommands:
        arp              test connectivity by arp
        icmp             test connectivity by icmp
        tcp              test connectivity by tcp

Subcommands for help:
        commands         list all command names
        flags            describe all known top-level flags
        help             describe subcommands and their syntax

$ ./boop help arp
arp [-i string] <target ip>:
        test connectivity by arp

  -i string
        source interface name

$ ./boop help icmp
arp [-6] <target host>:
        test connectivity by icmp

  -6    use ipv6

$ ./boop help tcp                                                                                                                                                                                                                                                   0s 󰅐 23:55:44
arp [-6] <target host> <target port>:
        test connectivity by tcp

  -6    use ipv6
```
