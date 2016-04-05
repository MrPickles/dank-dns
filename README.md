# Dank DNS

DankDNS is a DNS pcap processing tool that will all your dreams come true by taking pcaps with DNS queries and putting the question/response pairs into a format that is directly readable by disk. Notice that I am purposefully being vague due to a lack of implementation here. Will we write C structs directly to disk? Use a database? Stay tuned to find out!

## Prerequisites
* [CMake](https://github.com/Kitware/CMake)
* [libpcap](https://github.com/the-tcpdump-group/libpcap)
* [sparsehash](https://github.com/sparsehash/sparsehash)

## Building

1. Install dependencies.
   ```
   sudo apt-get install cmake libpcap-dev -y
   git clone https://github.com/sparsehash/sparsehash && cd sparsehash
   ./configure && make && sudo make install
   ```

2. Clone this repo.
   ```
   git clone <URL of repo>
   ```

3. Run CMake and Make to compile the parser.
   ```
   cd /path/to/bin
   cmake /path/to/repo
   make
   ```

## Usage

This part is subject to change (drastically). But for right now, usage should probably be something like the following:

```
./loader <directory full of pcaps> <output directory>
```

