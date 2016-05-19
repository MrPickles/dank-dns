# Dank DNS

Dank DNS is a DNS PCAP processing tool that will efficiently stream compressed
PCAPs to be loaded into a database.

## Components

The legacy implementation is located in `cpp/`. It contains the single threaded
processor that does all processing in memory via the tool.

The proof of concept implementation is written in JavaScript and is in `js`. It
implements all of the optimizations in JavaScript and writes the DNS query data
to MongoDB.

The improved C implementation is in `multiC`. This code multiprocesses the
loading of the DNS data into MongoDB. More details can be found in the README
in its specific folder.

