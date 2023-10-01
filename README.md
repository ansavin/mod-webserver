# mod-webserver

Stub webserver in kernel, that always send you `HTTP/1.1 200 OK` response with body `PONG`
Server listens to TCP port 2000 on all interfaces (currently this is hardcoded)

## Building & using module

### Linux version

Tested Linux kernel version is v6.4.11

### Using make

```bash
# build for host system
make KSRC=/lib/modules/$(uname -r)/build

# load module
insmod mod-webserver.ko [host=127.0.0.1] [port=2000]

# unload module
rmmod mod-webserver.ko

# clean up
make KSRC=/lib/modules/$(uname -r)/build clean
```

### Using DKMS

```bash
cd mod-webserver

# add module source to /usr/src tree
dkms add $(pwd)

# build & install module to /lib/modules/$(uname -r) tree
dkms install mod-webserver/1.0

# load module
modprobe -v mod-webserver

# unload module
rmmod mod-webserver

# remove it from DKMS tree
dkms remove mod-webserver/1.0 --all
```

### Using module

After loading module creates path in `/sys/kernel` only.
To start a webserver in current net ns, you need to write `1` in `/sys/kernel/webserver/status` path.
To start a webserver in new/exitsting net ns, you should enter this ns, mount sysfs and write `1` in `/sys/kernel/webserver/status`.
To disable webserver in current net ns, you need to write `0` in `/sys/kernel/webserver/status` path.
Disabling webserver in one ns shouldn't somehow affect webservers in other net namespaces.
Disabling webserver shouldn't affect sysfs and especially `/sys/kernel/webserver` created by module.
By entering new net ns (`unshare -t net sh`) and mounting sysfs (`mount -t sysfs sysfs /mnt`) you can run multiple instances of webserver on a single host
Don't forget to check if localhost is working in this net ns using `ip a`
Otherwise you have to up this interface by following commands: `ip addr add 127.0.0.1/8 dev lo && ip link set dev lo up`
Removing module leads to stopping webservers in all net ns.
Removing module removes /sys/kernel/webserver - and this is the only way to remove it.

## Developing module

### Test cases

Test cases are keywords-like scenarios for testing webserver's functionality and also a kind of documentation (see tests as docs concept)

#### Essential

- we can load module without kernel oops
- we can remove module without kernel oops

#### Basic usage

- we can load module without kernel oops
- adding module leads to creation `/sys/kernel/webserver`
- `echo 1 > /sys/kernel/webserver...` leads to enabling webserver (`nc localhost 2000` return message)
- `echo 123 > /sys/kernel/webserver...` (or any data except `1` or `0`) returns error and doesn't affect webserver
- `echo 0 > /sys/kernel/webserver...` leads to disabling webserver (`nc localhost 2000` return nothing)
- we can remove module without kernel oops

#### Multiple net NS usage

- we can load module without kernel oops
- adding module leads to creation `/sys/kernel/webserver`
- `echo 1 > /sys/kernel/webserver...` leads to enabling webserver (`nc localhost 2000` return message)
- entering net ns (`unshare -t net sh`) leads to non-working webserver in this ns and doesn't generate kernel oops
- mounting sysfs (`mount -t sysfs sysfs /mnt`) doesn't generate kernel oops
- `echo 1 > /mnt/sysfs/webserver...` (mounted sysfs) leads to enabling webserver (`nc localhost 2000` return message)
- `echo 0 > /mnt/sysfs/webserver...` (mounted sysfs) leads to disabling webserver (`nc localhost 2000` return nothing)
- returning to old net ns (^D) leads to still working webserver (`nc localhost 2000` return message)
- we can remove module without kernel oops

#### Custom host/port

- we can load module with custom params (host/port) without kernel oops
- `echo 1 > /sys/kernel/webserver...` leads to enabling webserver (`nc ...` return message)
- `echo 0 > /sys/kernel/webserver...` leads to disabling webserver (`nc ...` return nothing)
- we can remove module with custom params without kernel oops
