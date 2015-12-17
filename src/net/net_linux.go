package net

import (
    "os"
    "syscall"
)

// Get original destination from redirect of iptables.
func (c *conn) GetOriginalDestination() (addr *TCPAddr, err error) {
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

// Bind a UDP connection with the address.
func (a *UDPAddr) Bind(net, device string, transparent, recoverOriginalDestination bool) (*UDPConn, error) {
    family, sotype := syscall.AF_INET, syscall.SOCK_DGRAM
    if net[len(net)-1] == '6' {
        family = syscall.AF_INET6
    }

    s, err := sysSocket(family, sotype, 0)
    if err != nil {
        return nil, err
    }

    if err = setDefaultSockopts(s, family, sotype, false); err != nil {
        closeFunc(s)
        return nil, err
    }

    if transparent {
        if err = syscall.SetsockoptInt(s, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
            closeFunc(s)
            return nil, os.NewSyscallError("setsockopt", err)
        }
    }

    if recoverOriginalDestination {
        if err = syscall.SetsockoptInt(s, syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1); err != nil {
            closeFunc(s)
            return nil, os.NewSyscallError("setsockopt", err)
        }
    }

    if len(device) > 0 {
        if err = syscall.BindToDevice(s, device); err != nil {
            closeFunc(s)
            return nil, err
        }
    }

    var fd *netFD
    if fd, err = newFD(s, family, sotype, net); err != nil {
        closeFunc(s)
        return nil, err
    }

    lsa, err := a.sockaddr(fd.family)
    if (err == nil) && (lsa != nil) {
        if err = syscall.Bind(fd.sysfd, lsa); err != nil {
            err = os.NewSyscallError("bind", err)
        }
    }

    if err != nil {
        fd.Close()
        return nil, err
    }

    if err = fd.init(); err != nil {
        fd.Close()
        return nil, err
    }
    lsa, _ = syscall.Getsockname(fd.sysfd)
    fd.setAddr(fd.addrFunc()(lsa), nil)

    return newUDPConn(fd), nil
}
