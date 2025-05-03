package main

import (
	"errors"
	"net"
)

func parseIP(s string) (net.IP, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, errors.New("'" + s + "' is invalid ip")
	}

	return ip, nil
}

func getInterface(s string) (*net.Interface, error) {
	if s != "" {
		iface, err := net.InterfaceByName(s)
		if err != nil {
			return nil, err
		}
		return iface, nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// Looking for the default network interface
	for _, iface := range ifaces {
		if (iface.Flags&net.FlagUp) != 0 && (iface.Flags&net.FlagLoopback) == 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, err
			}

			for _, addr := range addrs {
				ipnet, ok := addr.(*net.IPNet)
				if ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
					return &iface, nil
				}
			}
		}
	}

	return nil, errors.New("default network interface not found")
}

func getInterfaceIPv4(iface *net.Interface) (*net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return &ipnet.IP, nil
			}
		}
	}
	return nil, errors.New("no ip v4 address found")
}

func isIPv6(ip net.IP) bool {
	return ip.To4() == nil && ip.To16() != nil
}
