package net

import (
    "os"
    "syscall"
)

// BindToDevice binds a UDPConn to a network interface.
func (c *UDPConn) BindToDevice(device string) error {
    if !c.ok() {
        return os.ErrInvalid
    }
    c.fd.incref()
    defer c.fd.decref()
    return os.NewSyscallError("setsockopt", syscall.BindToDevice(c.fd.sysfd, device))
}