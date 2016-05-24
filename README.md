# Dank DNS

Dank DNS is a DNS PCAP processing tool that will efficiently stream compressed
PCAPs to be loaded into a database.

## Components

The legacy implementation is located in `cpp/`. It contains the single threaded
processor that does all processing in memory via the tool.

The proof of concept implementation is written in JavaScript and is in `js/`. It
implements all of the optimizations in JavaScript and writes the DNS query data
to MongoDB.

The improved C implementation is in `multiC/`. This code multiprocesses the
loading of the DNS data into MongoDB. More details can be found in the
`README.md` file in its specific folder.

## Database Schema
The database will hold a collection of DNS queries. Specifically, each query
will have the following schema:

  - `node`: the replica from which the query originates (e.g. cpmd)
  - `time`: the timestamp of the query
  - `reqIP`: the IP address of the entity that made the request
  - `resIP`: this IP of the entity that provides the response (this should
always be 199.7.91.13)
  - `aa`: the value of the AA bit in the DNS query
  - `tc`: the value of the TC bit in the DNS query
  - `rd`: the value of the RD bit in the DNS query
  - `ra`: the value of the RA bit in the DNS query
  - `rc`: the value of the RC bit in the DNS query
  - `question`: the question of the DNS query (this comprises three parts)
    - `name`: the domain name in the query
    - `type`: the query type
    - `class`: the query class
  - `DNSSEC`: whether the query uses DNSSEC
  - `questionCount`: the question count for the query
  - `answerCount`: the answer count for the query
  - `authorityCount`: the authority count for the query
  - `additionalCount`: the additional count for the query

For additional details about database interactions, see any documentation in
the respective subdirectories.

