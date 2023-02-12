# mod-webserver

Stub webserver in kernel that always send you `HTTP/1.1 200 OK` response with body `PONG`.
Server listens to TCP port 2000 on all interfaces (currently this is hardcoded)

## Building & using module

### Using make

```
# build
make KSRC=/lib/modules/$(uname -r)/build

# load module
insmod mod-webserver.ko

# unload module
rmmod mod-webserver.ko

# clean up
make KSRC=/lib/modules/$(uname -r)/build clean
```

### Using DKMS

```
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
