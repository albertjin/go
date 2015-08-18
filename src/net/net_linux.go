package net

import (
    "os"
    "syscall"
)

// Get original destination from redirect of iptables.
func (c *conn) GetOriginalDestination(addr *TCPAddr, err error) {
    if !c.ok() {
        err = os.ErrInvalid
        return
    }
    c.fd.incref()
    defer c.fd.decref()

    const SO_ORIGINAL_DST = 80

    var a *syscall.IPv6Mreq
    if a, err = syscall.GetsockoptIPv6Mreq(c.fd.sysfd, syscall.SOL_IP, SO_ORIGINAL_DST); err == nil {
        data := a.Multiaddr
        addr = &TCPAddr{ IP: IP(data[4:8]), Port: int(data[2])<<8 + int(data[3]) }
    } else {
        err = os.NewSyscallError("getsockopt", err)
    }
    return
}

// BindToDevice binds a UDPConn to a network interface.
func (c *conn) BindToDevice(device string) error {
    if !c.ok() {
        return os.ErrInvalid
    }
    c.fd.incref()
    defer c.fd.decref()

    return os.NewSyscallError("setsockopt", syscall.BindToDevice(c.fd.sysfd, device))
}
