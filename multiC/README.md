# Dank DNS: Improved C Implementation

The improved implementation of the DNS processor includes three major
optimizations.

  - The processing of each PCAP is multiprocessed, allowing the processing to
saturate the CPU core usage and disk I/O resources.
  - Instead of traditional decompression of the PCAP files, we stream the
uncompressed PCAP data directly within our processor use `zcat`. This allows us
to avoid any overhead of having the uncompressed PCAP on disk.
  - Our PCAP data is loaded in MongoDB, and further metrics about the data are
queried out of the database instead of being measured within a processing
script. As a result, the data is within a structure optimized to gather metrics
about data.

## Dependencies
* [libpcap](https://github.com/the-tcpdump-group/libpcap)
* [MongoDB C Driver](https://github.com/mongodb/mongo-c-driver) (built locally)

## Build
1. Install dependencies.
   ```bash
   sudo apt-get install libpcap-dev -y
   ```

2. Configure and compile the processor. Configuration definitions are in
`config.h`. Within that file, you can set the database name, collection, cache
size, port, and even whether to use a database. The `configure` script to fetch
third party dependencies and check that the dynamic library path is set.
   ```bash
   vim config.h # edit definitions to your choosing
   ./configure && make
   ```

3. Set the path for the dynamic libraries (required for MongoDB usage).
   ```bash
   export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD/local/lib
   ```

4. To clean out all the binaries and object files, run the the `clean` Makefile
target. To clean out all binaries, object files, and third party dependencies
(e.g. the MongoDB C Driver), run the `distclean` target.
   ```bash
   make clean
   make distclean
   ```

## Usage

The usage for the processor is shown below. Worker count defaults to the number
of cores in the machine.
   ```bash
   ./main -i <pcap.gz files> [-w <worker count>]
   ```

The executable supports globbing for the arguments, so you can use that to your
advantage when processing larger batches of PCAPS.

Here is an example of proper usage when analyzing all traffic comining from
Seoul, Korea in the month of February 2016.
   ```bash
   ./main -i /fs/nm-dns/jeney-daily/sekr/2016-02-*/*
   ```

Optionally, to run tests, there is a target in the Makefile.
   ```bash
   make check
   ```

