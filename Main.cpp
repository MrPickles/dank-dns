#include <algorithm>
#include <arpa/inet.h>
#include <assert.h>
#include <bitset>
#include <ctype.h>
#include <dirent.h>
#include <list>
#include <math.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <regex.h>
#include <pcap/pcap.h>
#include <sparsehash/dense_hash_map>
#include <sparsehash/dense_hash_set>
#include <sparsehash/sparse_hash_map>
#include <sparsehash/sparse_hash_set>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <vector>

#include "Config.h"
#include "nameser.h"
#include "ParseDNS.h"
#include "StringHash.h"

using namespace std;
using namespace google;

////////////////////////////////////////////////////////////////////////////////
// Indexing into data structures that hold information on both the new and old
// IP addresses, additionally breaking this down into before or after the old
// server started announcing the new IP address.
//
//     Old Before -> 0    New Before -> 2
//     Old After  -> 1    New After  -> 3
//

inline int getIndex(uint64_t time, uint32_t destIP) {
  return (2 * (destIP == NEW_ADDRESS)) + (time >= TIME_OLD_ADVERT_NEW);
}

////////////////////////////////////////////////////////////////////////////////
// Other general variables for all analysis functions

struct Packet {
  uint64_t uniqueID;
  uint64_t time;
  uint64_t curCaptureTime;
  uint64_t lastCaptureTime;
  uint64_t overallCaptureTime;
  uint32_t sourceIP;
  uint32_t destIP;
  uint8_t payload[2048];
  size_t size;
};

// Previous parse output information
const char *anomalousFile = NULL;
typedef dense_hash_set<uint32_t> AnomalousSet;
AnomalousSet anomalous;

////////////////////////////////////////////////////////////////////////////////
// Analysis - Shared sourceIP -> info data structure
//
// Uses Google's sparse_hash_map, which has an overhead of around 2.67 bits per
// entry when using 64 bit pointers.
//

#define STATE_OLD   0
#define STATE_NEW   1
#define STATE_NONE  2

struct IPInfo {
  // Analysis - SCS
  uint64_t counts[4];
  uint64_t failures;
  uint8_t lastState;
  uint64_t numSwaps;

  // Analysis - QPHN
  uint64_t hourCountOld;
  uint64_t hourCountNew;
  uint64_t hourCountFailures;

  IPInfo() {
    memset(counts, 0, sizeof(counts));
    lastState = STATE_NONE;
    numSwaps = 0;
    failures = 0;
    hourCountOld = 0;
    hourCountNew = 0;
    hourCountFailures = 0;
  }
};

typedef sparse_hash_map<uint32_t, IPInfo> AddressToInfoMap;

AddressToInfoMap addressToInfo;

////////////////////////////////////////////////////////////////////////////////
// Analysis - Source Counts and Swaps (SCS)
//
// Records the number of queries sent to both the new and old IP addresses
// before/after the old server started to advertise the new IP address. In
// addition, this notes the number of times (if any) the source switched between
// querying the old and new IP addresses.
//
// In addition, records the time when a source switches from initially querying
// the old IP address to new one. Note that this will not count a transition
// such as New -> Old -> New.
//
// Also captures unique IP addresses that queried the old server more than 3
// times after the switch occured. This lower bound (3) is used to avoid priming
// queries, which occur under correct resolver operation.
//

FILE *scsLog;
FILE *scsTimesLog;
FILE *scsOldUniqueLog;
bitset<(1ULL << 32)> *scsOldUniqueNoted;

void startSCS(const char *outputDir) {
  char filePath[512];
  sprintf(filePath, "%s/%s", outputDir, "source-counts-swaps.log");
  if((scsLog = fopen(filePath, "w")) == NULL) {
    fprintf(stderr, "Could not open output log file '%s'\n", filePath);
    exit(1);
  }

  sprintf(filePath, "%s/%s", outputDir, "swap-times.log");
  if((scsTimesLog = fopen(filePath, "w")) == NULL) {
    fprintf(stderr, "Could not open output log file '%s'\n", filePath);
    exit(1);
  }

  sprintf(filePath, "%s/%s", outputDir, "old-unique.log");
  if((scsOldUniqueLog = fopen(filePath, "w")) == NULL) {
    fprintf(stderr, "Could not open output log file '%s'\n", filePath);
    exit(1);
  }

  scsOldUniqueNoted = new bitset<(1ULL << 32)>();
}

void analyzeSCS(Packet *p, const char *sourceIPStr, IPInfo *sourceInfo,
                DNSQuery *query) {
  sourceInfo->counts[getIndex(p->time, p->destIP)]++;

  // Checking if there have been SCS_OLD_UNIQUE_THRESHOLD queries after the old
  // server started advertising the new IP address
  if(sourceInfo->counts[1] == SCS_OLD_UNIQUE_THRESHOLD &&
     !scsOldUniqueNoted->test(p->sourceIP)) {
    scsOldUniqueNoted->set(p->sourceIP);
    fprintf(scsOldUniqueLog, "%s\n", sourceIPStr);
  }

  // Checking for NXDOMAIN failures
  if(query->error == DNS_ERR_NAME_ERROR) {
    sourceInfo->failures++;
  }

  // Checking for a change in state (i.e. swapping from old->new/new->old)
  bool isDestIPNewAddress = (p->destIP == NEW_ADDRESS);
  if(sourceInfo->lastState == STATE_NONE) {
    sourceInfo->lastState = isDestIPNewAddress;
  } else if(sourceInfo->lastState != isDestIPNewAddress) {
    sourceInfo->lastState = isDestIPNewAddress;

    // Initial Old -> New swap happened
    if(sourceInfo->numSwaps == 0 && isDestIPNewAddress) {
      fprintf(scsTimesLog, "%s %lu\n", sourceIPStr, p->time);
    }

    // Should only need to keep track of 2^16-1 swaps, but just making sure
    // that we do not wrap around due to a crazy resolver.
    if(sourceInfo->numSwaps < ((1 << 16) - 1)) {
      sourceInfo->numSwaps++;
    }
  }
}

void endSCS() {
  fprintf(scsLog, "source oba oaa nba naa swaps failures\n");

  AddressToInfoMap::const_iterator it = addressToInfo.begin();
  while(it != addressToInfo.end()) {
    const IPInfo *sourceInfo = &it->second;
    const uint32_t sourceIP = htonl(it->first); // Converting it back for ntop

    char sourceIPStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sourceIP, sourceIPStr, INET_ADDRSTRLEN);

    fprintf(scsLog, "%s %lu %lu %lu %lu %lu %lu\n", sourceIPStr,
            sourceInfo->counts[0], sourceInfo->counts[1],
            sourceInfo->counts[2], sourceInfo->counts[3],
            sourceInfo->numSwaps, sourceInfo->failures);

    it++;
  }

  fclose(scsLog);
  fclose(scsTimesLog);
  fclose(scsOldUniqueLog);
}

////////////////////////////////////////////////////////////////////////////////
// Analysis - Traffic Validity
//
// Determining the amount of valid/invalid traffic for the both the new and old
// IP address, before and after the old server started announcing the new IP
// address. In addition, for any invalid traffic breaking the TLD rule (#3), we
// keep track of the number of infractions for each unique TLD.
//
// I am basing the rules on valid/invalid traffic from the papers "A Day at the
// Root of the Internet" (SIGCOMM 08) and "Wow, That's a Lot of Packets" (PAM
// 03). The rules are in sorted order of priority in the structure below,
// meaning that we attribute only 1 invalidation reason to each query.
//

struct TVInfo {
  uint64_t nTotal;
  uint64_t nMalformed;
  uint64_t nInvalidClass;
  uint64_t nAForA;
  uint64_t nInvalidTLD;
  uint64_t nNonPrintChar;
  uint64_t nUnderscore;
  uint64_t nPrivateAddrPTR;

  uint64_t nIdentical;
  uint64_t nRepeated;
  uint64_t nReferralNotCached;
};

FILE *tvLog;
TVInfo tvInfo[4] = { 0 };

regex_t tvRegexAForA;

uint32_t tv8Prefix = 10;
uint32_t tv8Mask = 0xFF;
uint32_t tv12Prefix = (16 << 8) + 172;
uint32_t tv12Mask = 0xFFF;
uint32_t tv16Prefix = (168 << 8) + 172;
uint32_t tv16Mask = 0xFFFF;

// NOTE: Variable name must be globally unique for the template
extern const uint8_t tvKey[16];
const uint8_t tvKey[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6 };
typedef sparse_hash_map<const char *, uint64_t, StringHash<tvKey>, StringEqual>
        InvalidTLDToCountMap;

FILE *tvInvalidTLDLog;
InvalidTLDToCountMap tvInvalidTLDCounts;

void startTV(const char *outputDir) {
  char filePath[512];
  sprintf(filePath, "%s/%s", outputDir, "traffic-validity.log");
  if((tvLog = fopen(filePath, "w")) == NULL) {
    fprintf(stderr, "Could not open output log file '%s'\n", filePath);
    exit(1);
  }

  sprintf(filePath, "%s/%s", outputDir, "invalid-tlds.log");
  if((tvInvalidTLDLog = fopen(filePath, "w")) == NULL) {
    fprintf(stderr, "Could not open output log file '%s'\n", filePath);
    exit(1);
  }

  const char *expr = "^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)(\\.|$)){4}";
  if(regcomp(&tvRegexAForA, expr, REG_EXTENDED | REG_NOSUB)) {
    fprintf(stderr, "Could not compile regex (A for A)\n");
    exit(1);
  }
}

void analyzeTV(Packet *p, DNSQuery *query) {
  TVInfo *toUpdate = &tvInfo[getIndex(p->time, p->destIP)];
  toUpdate->nTotal++;

  // Rule 0 - Malformed query packet
  if(query->error == DNS_ERR_FORMAT_ERROR ||
     query->error == DNS_ERR_SERVER_FAILURE) {
    toUpdate->nMalformed++;
    return;
  }

  // [PRE-PROCESSING] Rule 3 - Invalid top level domain in query
  bool isValidRule3 = (query->error != DNS_ERR_NAME_ERROR);
  if(!isValidRule3) {
    InvalidTLDToCountMap::iterator it = tvInvalidTLDCounts.find(query->question.qnameParts.back().c_str());
    if(it != tvInvalidTLDCounts.end()) {
      it->second++;
    } else {
      tvInvalidTLDCounts.insert(make_pair(strdup(query->question.qnameParts.back().c_str()), 1));
    }
  }

  // Rule 1 - Invalid class
  if(!dnsIsValidClass(query->question.qclass)) {
    toUpdate->nInvalidClass++;
    return;
  }

  // Rule 2 - Type A query which specifies an IP address as the domain name
  if(query->question.qtype == T_A) {
    if(regexec(&tvRegexAForA, query->question.qname.c_str(), 0, NULL, 0) == 0) {
      toUpdate->nAForA++;
      return;
    }
  }

  // Rule 3 - Invalid top level domain in query (ignore root zone queries)
  if(!isValidRule3) {
    toUpdate->nInvalidTLD++;
    return;
  }

  // Rule 4 - Domain name contains non-printable characters
  // Rule 5 - Domain name contains underscore '_' character
  for(int c = 0; c < query->question.qname.length(); c++) {
    if(isprint(query->question.qname[c]) == 0) {
      toUpdate->nNonPrintChar++;
      return;
    } else if(query->question.qname[c] == '_') {
      toUpdate->nUnderscore++;
      return;
    }
  }

  // Rule 6 - PTR query for IP address from private address space (RFC 1918)
  if(query->question.qtype == T_PTR) {
    size_t endPos = query->question.qname.find(".in-addr.arpa");
    if(endPos != string::npos && endPos < INET_ADDRSTRLEN) {
      char queryIPStr[INET_ADDRSTRLEN] = { 0 };
      memcpy(queryIPStr, query->question.qname.c_str(), endPos);

      // Currently ignoring when the conversion fails due to invalid IP address
      // string, as it seems that the previous papers make to mention of this.
      uint32_t queryIP;
      if(inet_pton(AF_INET, queryIPStr, &queryIP) > 0) {
        if((queryIP & tv8Mask) == tv8Prefix ||   // 10/8 prefix
           (queryIP & tv12Mask) == tv12Prefix || // 172.16/12 prefix
           (queryIP & tv16Mask) == tv16Prefix) { // 192.168/16 prefix
          toUpdate->nPrivateAddrPTR++;
          return;
        }
      }
    }
  }
}

void endTV() {
  fprintf(tvLog, "total malformed invalidclass afora invalidtld nonprintchar underscore privateaddrptr\n");
  for(int i = 0; i < 4; i++) {
    fprintf(tvLog, "%lu %lu %lu %lu %lu %lu %lu %lu\n", tvInfo[i].nTotal,
            tvInfo[i].nMalformed, tvInfo[i].nInvalidClass, tvInfo[i].nAForA,
            tvInfo[i].nInvalidTLD, tvInfo[i].nNonPrintChar,
            tvInfo[i].nUnderscore, tvInfo[i].nPrivateAddrPTR);
  }
  fclose(tvLog);

  fprintf(tvInvalidTLDLog, "invalidtld count\n");
  InvalidTLDToCountMap::const_iterator it = tvInvalidTLDCounts.begin();
  while(it != tvInvalidTLDCounts.end()) {
    fprintf(tvInvalidTLDLog, "%s %lu\n", it->first, it->second);
    it++;
  }
  fclose(tvInvalidTLDLog);

  regfree(&tvRegexAForA);
}

////////////////////////////////////////////////////////////////////////////////
// Analysis - Types of Queries (TOQ)
//
// Records the total number of each type of query sent to both the old and new
// IP addresses. Malformed queries (in terms of structure, not due to the use of
// invalid types/classes) are placed in their own catagory.
//

struct TOQInfo {
  uint64_t types[1 << 16];
  uint64_t classes[1 << 16];
  uint64_t typesFailures[1 << 16]; 
  uint64_t nError; 
};

FILE *toqLog;
TOQInfo toqInfo[4] = { 0 };

void startTOQ(const char *outputDir) {
  char filePath[512];
  sprintf(filePath, "%s/%s", outputDir, "types-of-queries.log");
  if((toqLog = fopen(filePath, "w")) == NULL) {
    fprintf(stderr, "Could not open output log file '%s'\n", filePath);
    exit(1);
  }
}

void analyzeTOQ(Packet *p, DNSQuery *query) {
  TOQInfo *toUpdate = &toqInfo[getIndex(p->time, p->destIP)];

  if(query->error != DNS_ERR_FORMAT_ERROR &&
     query->error != DNS_ERR_SERVER_FAILURE) {
    toUpdate->types[query->question.qtype]++;
    toUpdate->classes[query->question.qclass]++;

    if(query->error != 0) {
      toUpdate->typesFailures[query->question.qtype]++;
    }
  } else {
    toUpdate->nError++;
  }
}

void endTOQ() {
  fprintf(toqLog, "obt obtf obc obe oat oatf oac oae nbt nbtf nbc nbe nat natf nac nae\n");

  fprintf(toqLog, "%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
          toqInfo[0].types[0], toqInfo[0].typesFailures[0], toqInfo[0].classes[0], toqInfo[0].nError,
          toqInfo[1].types[0], toqInfo[1].typesFailures[0], toqInfo[1].classes[0], toqInfo[1].nError,
          toqInfo[2].types[0], toqInfo[2].typesFailures[0], toqInfo[2].classes[0], toqInfo[2].nError,
          toqInfo[3].types[0], toqInfo[3].typesFailures[0], toqInfo[3].classes[0], toqInfo[3].nError); 

  for(int i = 1; i < (1 << 16); i++) {
    fprintf(toqLog, "%lu %lu %lu - %lu %lu %lu - %lu %lu %lu - %lu %lu %lu -\n", 
            toqInfo[0].types[i], toqInfo[0].typesFailures[i], toqInfo[0].classes[i],
            toqInfo[1].types[i], toqInfo[1].typesFailures[i], toqInfo[1].classes[i],
            toqInfo[2].types[i], toqInfo[2].typesFailures[i], toqInfo[2].classes[i],
            toqInfo[3].types[i], toqInfo[3].typesFailures[i], toqInfo[3].classes[i]); 
  }

  fclose(toqLog);
}

////////////////////////////////////////////////////////////////////////////////
// Analysis - Queries per Second over an Hour (QPH)
//
// Performed both on an overall level, and per source.
//

FILE *qphLog;
FILE *qphSourceLog;
uint64_t qphStartTime;
uint64_t qphActualTime;
uint64_t qphOldCount;
uint64_t qphNewCount;
bitset<(1ULL << 32)> *qphIsUniqueOld;
bitset<(1ULL << 32)> *qphIsUniqueNew;
uint64_t qphNumUniqueOld;
uint64_t qphNumUniqueNew;

void startQPH(const char *outputDir) {
  char filePath[512];
  sprintf(filePath, "%s/%s", outputDir, "qph-overall.log");
  if((qphLog = fopen(filePath, "w")) == NULL) {
    fprintf(stderr, "Could not open output log file '%s'\n", filePath);
    exit(1);
  }

  sprintf(filePath, "%s/%s", outputDir, "qph-source.log");
  if((qphSourceLog = fopen(filePath, "w")) == NULL) {
    fprintf(stderr, "Could not open output log file '%s'\n", filePath);
    exit(1);
  }

  qphIsUniqueOld = new bitset<(1ULL << 32)>();
  qphIsUniqueNew = new bitset<(1ULL << 32)>();

  qphStartTime = 0;
  qphActualTime = 0;
  qphOldCount = 0;
  qphNewCount = 0;
  qphNumUniqueOld = 0;
  qphNumUniqueNew = 0;

  fprintf(qphLog, "time old new oldunique newunique\n");
  fprintf(qphSourceLog, "source old new failures\n");
}

void analyzeQPH(Packet *p, IPInfo *sourceInfo, DNSQuery *query) {
  if((p->time - qphStartTime) > TIME_S2US(60 * 60)) {
    if(qphStartTime != 0) {
      fprintf(qphLog, "%lu %lu %lu %lu %lu\n", qphStartTime,
              (uint64_t)(qphOldCount / TIME_US2S(qphActualTime)),
              (uint64_t)(qphNewCount / TIME_US2S(qphActualTime)),
              (uint64_t)(qphNumUniqueOld / TIME_US2S(qphActualTime)),
              (uint64_t)(qphNumUniqueNew / TIME_US2S(qphActualTime)));

      fprintf(qphSourceLog, "# time %lu\n", qphStartTime);
      AddressToInfoMap::iterator it = addressToInfo.begin();
      while(it != addressToInfo.end()) {
        IPInfo *info = &it->second;

        if(info->hourCountOld > 0 ||
           info->hourCountNew > 0) {
          uint32_t sourceIPNet = htonl(it->first); // Converting it back

          char sourceIPStr[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &sourceIPNet, sourceIPStr, INET_ADDRSTRLEN);
          
          fprintf(qphSourceLog, "%s %lu %lu %lu\n", sourceIPStr, info->hourCountOld,
                  info->hourCountNew, info->hourCountFailures); 
        }

        info->hourCountOld = 0;
        info->hourCountNew = 0;
        info->hourCountFailures = 0;

        it++;
      }
    }

    qphStartTime = p->time - (p->time % TIME_S2US(60 * 60));
    qphActualTime = 0;
    qphOldCount = 0;
    qphNewCount = 0;
    qphIsUniqueOld->reset();
    qphIsUniqueNew->reset();
    qphNumUniqueOld = 0;
    qphNumUniqueNew = 0;
  }

  if(p->destIP == OLD_ADDRESS) {
    if(!qphIsUniqueOld->test(p->sourceIP)) {
      qphNumUniqueOld++;
      qphIsUniqueOld->set(p->sourceIP);
    }
    qphOldCount++;
    sourceInfo->hourCountOld++;
  } else {
    if(!qphIsUniqueNew->test(p->sourceIP)) {
      qphNumUniqueNew++;
      qphIsUniqueNew->set(p->sourceIP);
    }
    qphNewCount++;
    sourceInfo->hourCountNew++;
  }

  if(query->error != 0) {
    sourceInfo->hourCountFailures++;
  }
}

void endQPH() {
  fclose(qphLog);
  fclose(qphSourceLog);
}

////////////////////////////////////////////////////////////////////////////////
// Analysis - Anomalous Cases of Limpets and Excitables (ALE)
//

FILE *aleLog;

// Storing hashes because this gets way too out of control
extern const uint8_t aleKey[16];
const uint8_t aleKey[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6 };
StringHash<aleKey> aleHash;
//typedef sparse_hash_set<uint64_t> QueryNamesSet;
typedef sparse_hash_set<uint32_t> QueryNamesSet;

struct AnomalousInfo {
  uint64_t successes[4]; 
  uint64_t nxdomains[4]; 
  uint64_t malformed[4]; 
  uint64_t countsTotal[4];
  uint64_t counts24Hours[4];
  uint64_t typeACounts[4];
  uint64_t typeNSCounts[4];
  uint64_t typeSOACounts[4];
  uint64_t typeSRVCounts[4];
  uint64_t dnssecCount;
  uint64_t curCaptureCount;
  vector<uint64_t> captureCounts;
  //QueryNamesSet queryNames; 
  QueryNamesSet queryNamesSucc; 
  QueryNamesSet queryNamesFail; 
  sparse_hash_set<int> queryTypes; 

  AnomalousInfo() {
    memset(successes, 0, sizeof(successes)); 
    memset(nxdomains, 0, sizeof(nxdomains)); 
    memset(malformed, 0, sizeof(malformed)); 
    memset(countsTotal, 0, sizeof(countsTotal)); 
    memset(counts24Hours, 0, sizeof(counts24Hours));
    memset(typeACounts, 0, sizeof(typeACounts));
    memset(typeNSCounts, 0, sizeof(typeNSCounts));
    memset(typeACounts, 0, sizeof(typeACounts));
    memset(typeNSCounts, 0, sizeof(typeNSCounts));
    memset(typeSOACounts, 0, sizeof(typeSOACounts));
    memset(typeSRVCounts, 0, sizeof(typeSRVCounts));
    dnssecCount = 0;
    curCaptureCount = 0;
    captureCounts.clear();
  }
};

typedef sparse_hash_map<uint32_t, AnomalousInfo> AnomalousToInfoMap;
AnomalousToInfoMap anomalousToInfo;

void startALE(const char *outputDir) {
  char filePath[512];
  sprintf(filePath, "%s/%s", outputDir, "ale.log");
  if((aleLog = fopen(filePath, "w")) == NULL) {
    fprintf(stderr, "Could not open output log file '%s'\n", filePath);
    exit(1);
  }
}

void analyzeALE(Packet *p, DNSQuery *query) {
  // Skipping analysis if there was no prior output, or if this source is not
  // specified as a target
  if(anomalous.find(p->sourceIP) == anomalous.end()) {
    return;
  }

  AnomalousInfo *info = &anomalousToInfo[p->sourceIP];
  int index = getIndex(p->time, p->destIP);
  info->countsTotal[index]++;

  // Feature 1 - Number of DNSSEC queries
  if(query->error != DNS_ERR_FORMAT_ERROR &&
     query->error != DNS_ERR_SERVER_FAILURE) {
    if(query->isDNSSEC) {
      info->dnssecCount++;
    }
  }

  // Feature 2 - Number of queries after vs before (within 24 hours)
  if(p->time >= (TIME_OLD_ADVERT_NEW - TIME_S2US(24 * 60 * 60)) &&
     p->time <= (TIME_OLD_ADVERT_NEW + TIME_S2US(24 * 60 * 60))) {
    info->counts24Hours[index]++;
  }

  // Feature 3 - Frequency of ". IN" A, NS, SOA, SRV queries
  if(query->error == 0) {
    if(query->question.qname[0] == '.' &&
        query->question.qclass == C_IN) {
      switch(query->question.qtype) {
        case T_NS:
          info->typeNSCounts[index]++;
          break;
        case T_A:
          info->typeACounts[index]++;
          break;
        case T_SOA:
          info->typeSOACounts[index]++;
          break;
        case T_SRV:
          info->typeSRVCounts[index]++;
          break;
      }
    }
  }

  // Feature 4 - Checking for failures (NXDOMAIN/Malformed)
  if(query->error == 3) {
    info->nxdomains[index]++;
  } else if(query->error != 0) {
    info->malformed[index]++; 
  } else {
    info->successes[index]++; 
  }

  // Feature 5 - Peak to average query ratio
  // Feature 6 - Check for periodicity in queries over time
  // Both require just storing per-capture packet counts, which are later
  // modified by the duration of each capture
  info->curCaptureCount++;

  // Feature 7 - Noting the diversity in query names
  // Feature 8 - Noting the diversity in query types
  if(query->error != DNS_ERR_FORMAT_ERROR &&
     query->error != DNS_ERR_SERVER_FAILURE) {
    //uint64_t qnameHash = aleHash(query->question.qname.c_str());
    uint32_t qnameHash = (uint32_t)aleHash(query->question.qname.c_str()); 

    if(query->error == 3) {
      info->queryNamesFail.insert(qnameHash);
    }
    else {
      info->queryNamesSucc.insert(qnameHash);
    }

    //info->queryNames.insert(qnameHash);
    info->queryTypes.insert((int)query->question.qtype);
  }
}

void endALE() {
  fprintf(aleLog, "source obsucc oasucc nbsucc nasucc obnx oanx nbnx nanx "
          "obm oam nbm nam ob oa nb na ob24 oa24 nb24 na24 "
          "obta oata nbta nata obtns oatns nbtns natns obtsoa oatsoa "
          "nbtsoa natsoa obtsrv oatsrv nbtsrv natsrv dnssec max "
          "min mean p95 p5 namessucc namesfail types\n");

  AnomalousToInfoMap::iterator it = anomalousToInfo.begin();
  while(it != anomalousToInfo.end()) {
    AnomalousInfo *info = &it->second;
    const uint32_t sourceIP = htonl(it->first); // Converting it back for ntop

    char sourceIPStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sourceIP, sourceIPStr, INET_ADDRSTRLEN);

    // Feature 2 - Peak to average query ratio
    int numCaptures = info->captureCounts.size();
    sort(info->captureCounts.begin(), info->captureCounts.end());

    double queryMean = 0;
    vector<uint64_t>::const_iterator cIt = info->captureCounts.begin();
    while(cIt != info->captureCounts.end()) {
      queryMean += *cIt;
      cIt++;
    }
    queryMean /= numCaptures;

    uint64_t queryMin = info->captureCounts.front();
    uint64_t queryMax = info->captureCounts.back();
    uint64_t queryP5 = info->captureCounts[ceil(0.05 * numCaptures) - 1];
    uint64_t queryP95 = info->captureCounts[ceil(0.95 * numCaptures) - 1];

    // Feature 3 - Check for periodicity in queries over time

    // Finding the total energy in the signal, used to determine confidence
    // in the best correlation
    uint64_t totalEnergy = 0;
    for(int i = 0; i < numCaptures; i++) {
      totalEnergy += info->captureCounts[i] * info->captureCounts[i];
    }

    // Computing each lagged auto-correlation in order to find the best fit
    uint64_t bestCorr = 0;
    uint64_t bestLag = 0;

    fprintf(aleLog, "%s ", sourceIPStr);
    fprintf(aleLog, "%lu %lu %lu %lu ", info->successes[0], info->successes[1],
            info->successes[2], info->successes[3]);
    fprintf(aleLog, "%lu %lu %lu %lu ", info->nxdomains[0], info->nxdomains[1],
            info->nxdomains[2], info->nxdomains[3]); 
    fprintf(aleLog, "%lu %lu %lu %lu ", info->malformed[0], info->malformed[1], 
            info->malformed[2], info->malformed[3]); 
    fprintf(aleLog, "%lu %lu %lu %lu ", info->countsTotal[0],
            info->countsTotal[1], info->countsTotal[2], info->countsTotal[3]); 
    fprintf(aleLog, "%lu %lu %lu %lu ", info->counts24Hours[0],
            info->counts24Hours[1], info->counts24Hours[2],
            info->counts24Hours[3]);
    fprintf(aleLog, "%lu %lu %lu %lu ", info->typeACounts[0],
            info->typeACounts[1], info->typeACounts[2], info->typeACounts[3]); 
    fprintf(aleLog, "%lu %lu %lu %lu ", info->typeNSCounts[0],
            info->typeNSCounts[1], info->typeNSCounts[2],
            info->typeNSCounts[3]);
    fprintf(aleLog, "%lu %lu %lu %lu ", info->typeSOACounts[0],
            info->typeSOACounts[1], info->typeSOACounts[2],
            info->typeSOACounts[3]); 
    fprintf(aleLog, "%lu %lu %lu %lu ", info->typeSRVCounts[0],
            info->typeSRVCounts[1], info->typeSRVCounts[2],
            info->typeSRVCounts[3]);
    fprintf(aleLog, "%lu ", info->dnssecCount);
    fprintf(aleLog, "%lu %lu %lf %lu %lu ", queryMax, queryMin, queryMean,
            queryP95, queryP5);
    fprintf(aleLog, "%lu %lu %lu\n", info->queryNamesSucc.size(), 
            info->queryNamesFail.size(), info->queryTypes.size()); 

    it++;
  }

  fclose(aleLog);
}

////////////////////////////////////////////////////////////////////////////////
// Analysis - Queries per second (QPS)
//
// Measures the number of queries per second for both the new and old IP
// addresses. We only record values that take place over a full second interval
// (i.e. saw a ping in the second interval before and after the current
// interval). This is due to the non-contiguous nature of the data, with ~7
// seconds of queries every 1-30 minutes.
//
// In addition, we note the breakdown of the types of queries during each
// interval in order to build a stack plot of the XX most popular types over
// time.
//

struct QPSKeyValue {
  uint16_t k;
  uint64_t v;
};

struct QPSInfo {
  uint64_t oldCount;
  uint64_t newCount;
  QPSKeyValue oldTypes[1 << 16];
  QPSKeyValue newTypes[1 << 16];
  uint64_t oldDNSSECCount;
  uint64_t newDNSSECCount;
  uint64_t oldFailures;
  uint64_t newFailures;
}; 

FILE *qpsLog;

QPSInfo qpsInfo;
uint64_t qpsStartTime;
uint64_t qpsLastTime;
bool qpsIsValidStart;

void qpsResetInfo(QPSInfo *info) {
  info->oldCount = 0;
  info->newCount = 0;
  for(int i = 0; i < (1 << 16); i++) {
    info->oldTypes[i].k = i;
    info->oldTypes[i].v = 0;
    info->newTypes[i].k = i;
    info->newTypes[i].v = 0;
  }
  info->oldDNSSECCount = 0;
  info->newDNSSECCount = 0;
  info->oldFailures = 0;
  info->newFailures = 0; 
}

void startQPS(const char *outputDir) {
  char filePath[512];
  sprintf(filePath, "%s/%s", outputDir, "qps.log");
  if((qpsLog = fopen(filePath, "w")) == NULL) {
    fprintf(stderr, "Could not open output log file '%s'\n", filePath);
    exit(1);
  }

  fprintf(qpsLog, "time old new");
  for(int i = 0; i < QPS_MAX_TYPES; i++) {
    fprintf(qpsLog, " otv%d otc%d", i, i);
  }
  for(int i = 0; i < QPS_MAX_TYPES; i++) {
    fprintf(qpsLog, " ntv%d ntc%d", i, i);
  }
  fprintf(qpsLog, " osec nsec ofail nfail\n");

  qpsResetInfo(&qpsInfo);
  qpsStartTime = 0;
  qpsLastTime = 0;
  qpsIsValidStart = false;
}

int qpsUInt64Compare(const void *a, const void *b) {
  return (((QPSKeyValue *)b)->v - ((QPSKeyValue *)a)->v);
}

void analyzeQPS(Packet *p, DNSQuery *query) {
  // 1 second interval has passed
  if((p->time - qpsStartTime) > TIME_S2US(1)) {
    // Current packet is in next interval, so attempt to process and then mark
    // the next interval as a valid start
    if((qpsLastTime + TIME_S2US(1)) > p->time) {
      // Making sure we saw a packet in the previous interval in order to record
      // the data
      if(qpsIsValidStart) {
        qsort(qpsInfo.oldTypes, 1 << 16, sizeof(QPSKeyValue), qpsUInt64Compare);
        qsort(qpsInfo.newTypes, 1 << 16, sizeof(QPSKeyValue), qpsUInt64Compare);
        fprintf(qpsLog, "%lu %lu %lu", qpsStartTime, qpsInfo.oldCount,
                qpsInfo.newCount);
        for(int i = 0; i < QPS_MAX_TYPES; i++) {
          fprintf(qpsLog, " %hu %lu", qpsInfo.oldTypes[i].k,
                  qpsInfo.oldTypes[i].v);
        }
        for(int i = 0; i < QPS_MAX_TYPES; i++) {
          fprintf(qpsLog, " %hu %lu", qpsInfo.newTypes[i].k,
                  qpsInfo.newTypes[i].v);
        }
        fprintf(qpsLog, " %lu %lu %lu %lu\n", qpsInfo.oldDNSSECCount,
                qpsInfo.newDNSSECCount, qpsInfo.oldFailures,
                qpsInfo.newFailures);
      }

      qpsIsValidStart = true;
    }
    // Current packet is from a future interval (from another capture file) so
    // do not count the next interval
    else {
      qpsIsValidStart = false;
    }

    qpsResetInfo(&qpsInfo);
    qpsStartTime = p->time;
  }

  if(p->destIP == OLD_ADDRESS) {
    qpsInfo.oldCount++;
    if(query->error != DNS_ERR_FORMAT_ERROR &&
       query->error != DNS_ERR_SERVER_FAILURE) {
      qpsInfo.oldTypes[query->question.qtype].v++;

      if(query->isDNSSEC) {
        qpsInfo.oldDNSSECCount++;
      }
    }
    if(query->error != 0) {
      qpsInfo.oldFailures++;
    }
  } else {
    qpsInfo.newCount++;
    if(query->error != DNS_ERR_FORMAT_ERROR &&
       query->error != DNS_ERR_SERVER_FAILURE) {
      qpsInfo.newTypes[query->question.qtype].v++;

      if(query->isDNSSEC) {
        qpsInfo.newDNSSECCount++;
      }
    }
    if(query->error != 0) {
      qpsInfo.newFailures++;
    }
  }

  qpsLastTime = p->time;
}

void endQPS() {
  fclose(qpsLog);
}

////////////////////////////////////////////////////////////////////////////////
// HandlePacket
//
// Called from pcap_loop, this function breaks down the packet into its parts
// (IP, UDP, DNS) and calls all appropriate analysis functions with the
// necessary information. The compiled pcap rule limits calls to this function
// to UDP packets arriving/leaving on port 53 for the old/new IP addresses.
//

struct QRPacketPair {
  Packet q;
  Packet r;
  bool ready;
};

// Holding query+response pairs for future in-order processing
QRPacketPair *packets;
int packetProc = 0;
int packetAdd = 0;

// Keeping track of the amount of captured time
uint64_t totalCaptureTime = 0;
uint64_t lastCaptureTime = 0;
uint64_t captureStartTime = 0;
uint64_t captureLastTime = 0;
bool isFirstCapturePacket = false;
bool isFirstCapture = true;

// Since analysis functions may not always get called, perform the updates
// of their time keeping structures here
void updateAnalysisTimes(uint64_t time) {
  // Analysis - QPHN
  qphActualTime += (time - captureLastTime);

  // Analysis - ALE
  // Shifting current capture counts to the history once we hit a new capture
  if(!isFirstCapture && ((captureLastTime - captureStartTime) == 0)) {
    AnomalousToInfoMap::iterator it = anomalousToInfo.begin();
    while(it != anomalousToInfo.end()) {
      it->second.captureCounts.push_back(it->second.curCaptureCount / TIME_US2S(lastCaptureTime));
      it->second.curCaptureCount = 0;
      it++;
    }
  }
}

void processQueryResponse(QRPacketPair *pPair) {
  DNSQuery query = { 0 };
  Packet *q = &pPair->q;
  Packet *r = &pPair->r;

  // Parsing the DNS response for error conditions
  query.error = dnsParseResponse(r->payload, r->size);

  // Parsing the DNS query
  if(dnsParseQuery(&query, q->payload, q->size) < 0) {
    assert(false && "Failed to parse a successful DNS query");
  }

  // Gathering additional information used for analysis
  char sourceIPStr[INET_ADDRSTRLEN];
  uint32_t sourceIPNet = htonl(q->sourceIP);
  inet_ntop(AF_INET, &sourceIPNet, sourceIPStr, INET_ADDRSTRLEN);

  IPInfo *info = &addressToInfo[q->sourceIP];

  // Performing the analysis
  analyzeQPS(q, &query);
  //analyzeOAP(q, sourceIPStr, &query);
  analyzeTV(q, &query);
  analyzeTOQ(q, &query);
  analyzeSCS(q, sourceIPStr, info, &query);
  analyzeQPH(q, info, &query);
  analyzeALE(q, &query);
}

void handlePacket(uint8_t *arg, const struct pcap_pkthdr *header,
                  const uint8_t *packet) {
  const int datalinkOffset = *((int *)arg);
  uint64_t time = TIME_S2US(header->ts.tv_sec) + header->ts.tv_usec;

  // Updating the capture time keeping
  if(isFirstCapturePacket) {
    captureStartTime = time;
    captureLastTime = time;
    isFirstCapturePacket = false;
  }
  updateAnalysisTimes(time);
  captureLastTime = time;

  // Grabbing IP information, and applying any necessary rules
  const struct ip *headerIP = (const struct ip *)(packet + datalinkOffset);
  const uint8_t *payloadIP = (uint8_t *)headerIP + (headerIP->ip_hl * 4);
  uint32_t destIP = ntohl(headerIP->ip_dst.s_addr);
  uint32_t sourceIP = ntohl(headerIP->ip_src.s_addr);

  if(headerIP->ip_v != 4) {
    return;
  }

  // Grabbing the UDP information, and applying any necessary rules
  const struct udphdr *headerUDP = (const struct udphdr *)payloadIP;
  const uint8_t *payloadUDP = (uint8_t *)headerUDP + 8;
  const uint16_t payloadUDPSize = ntohs(headerUDP->len) - 8;
  uint16_t sourcePort = ntohs(headerUDP->source);
  uint16_t destPort = ntohs(headerUDP->dest);

  if(payloadUDPSize > 2048) {
    fprintf(stderr, "Payload > 2048 bytes, skipping\n");
    return;
  }

  // Grabbing just a tiny bit of DNS information, namely the query ID
  // in order to do query->response matching
  int queryID = dnsParseID(payloadUDP, payloadUDPSize);
  if(queryID >= 0) {
    // If this is a query, add it to the queue and packet info map so that  we
    // can later match it up with it's response
    if(destIP == OLD_ADDRESS || destIP == NEW_ADDRESS) {
      uint64_t uniqueID = ((uint64_t)sourceIP << 32) | ((uint64_t)sourcePort << 16) | queryID;

      packets[packetAdd].q.uniqueID = uniqueID;
      packets[packetAdd].q.time = time;
      packets[packetAdd].q.curCaptureTime = captureLastTime - captureStartTime;
      packets[packetAdd].q.lastCaptureTime = lastCaptureTime;
      packets[packetAdd].q.overallCaptureTime = totalCaptureTime;
      packets[packetAdd].q.sourceIP = sourceIP;
      packets[packetAdd].q.destIP = destIP;
      packets[packetAdd].q.size = payloadUDPSize;
      memcpy(packets[packetAdd].q.payload, payloadUDP, payloadUDPSize);

      packets[packetAdd].ready = false;
      packetAdd++;
    } else {
      // Otherwise, this is a result so look for the query packet and pair them
      uint64_t uniqueID = ((uint64_t)destIP << 32) | ((uint64_t)destPort << 16) | queryID;

      for(int i = packetAdd - 1; i >= packetProc; i--) {
        if(packets[i].q.uniqueID == uniqueID) {
          packets[i].r.uniqueID = uniqueID;
          packets[i].r.time = time;
          packets[i].r.curCaptureTime = captureLastTime - captureStartTime;
          packets[i].r.lastCaptureTime = lastCaptureTime;
          packets[i].r.overallCaptureTime = totalCaptureTime;
          packets[i].r.sourceIP = sourceIP;
          packets[i].r.destIP = destIP;
          packets[i].r.size = payloadUDPSize;
          memcpy(packets[i].r.payload, payloadUDP, payloadUDPSize);
          packets[i].ready = true;

          break;
        }
      }
    }
  }

  // Going through the list to check if we can process any more packets. We want
  // to issue packets in the same order as they arrived, just in case analysis
  // expects times to flow as such
  while((packetProc < packetAdd) && packets[packetProc].ready) {
    processQueryResponse(&packets[packetProc]);
    packetProc++;
  }
}

void startAllAnalysis(const char *outputDir) {
  dnsParseInit();

  packets = new QRPacketPair[200000];

  // Grabbing limpets and excitables information (if available)
  anomalous.set_empty_key(0);
  if(anomalousFile != NULL) {
    FILE *file = fopen(anomalousFile, "r"); 
    if(file == NULL) {
      fprintf(stderr, "Could not open input log file '%s'\n", anomalousFile); 
      exit(1);
    }

    uint64_t numSourcesAdded = 0;

    char line[32];
    while(fgets(line, sizeof(line), file) != NULL) {
      char sourceIPStr[1024];
      sscanf(line, "%s", sourceIPStr);
      uint32_t sourceIP = ntohl(inet_addr(sourceIPStr));
      if(sourceIP != 0xFFFFFFFF) {
        anomalous.insert(sourceIP);
        anomalousToInfo.insert(make_pair(sourceIP, AnomalousInfo()));
        numSourcesAdded++;
      }
    }

    fclose(file); 

    printf("Added %lu anomalous sources from '%s'\n", numSourcesAdded, anomalousFile);
  }

  startQPS(outputDir);
  startTV(outputDir);
  startTOQ(outputDir);
  startSCS(outputDir);
  startQPH(outputDir);
  startALE(outputDir);
}

void endAllAnalysis() {
  endQPS();
  endTV();
  endTOQ();
  endSCS();
  endQPH();
  endALE();
}

inline uint64_t getTimeMilliseconds() {
  struct timespec curTime;
  clock_gettime(CLOCK_REALTIME, &curTime);
  return ((uint64_t)curTime.tv_sec * 1000) + (curTime.tv_nsec / 1000000);
}

int main(int argc, char **argv) {
  if(argc < 3) {
    fprintf(stderr, "Usage: %s <capture dir> <output dir> [anomalous file] [start file #] [end file #]\n", argv[0]);
    exit(1);
  }

  // Previous parse output directory was specified
  if(argc > 3) {
    anomalousFile = argv[3];
  }

  int numEntries;
  struct dirent **entries;
  if((numEntries = scandir(argv[1], &entries, NULL, alphasort)) < 0) {
    fprintf(stderr, "Could not scan directory '%s'\n", argv[1]);
    exit(1);
  }

  char outputDir[512];
  sprintf(outputDir, "%s/output_%ld", argv[2], time(NULL));
  if(mkdir(outputDir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
    fprintf(stderr, "Could not create output directory '%s'\n", outputDir);
    exit(1);
  }

  startAllAnalysis(outputDir);

  // Using this file to record the capture length (in time) for each file
  FILE *capturelenLog;
  char filePath[512];
  sprintf(filePath, "%s/%s", outputDir, "capturelen.log");
  if((capturelenLog = fopen(filePath, "w")) == NULL) {
    fprintf(stderr, "Could not open output log file '%s'\n", filePath);
    exit(1);
  }

  int numEntriesParsed = 0;

  int eStart = (argc >= 5) ? atoi(argv[4]) : 0;
  int eEnd = (argc == 6) ? atoi(argv[5]) : numEntries;
  for(int e = eStart; e < eEnd; e++) {
    if(entries[e]->d_type == DT_REG) {
      uint64_t startProcTime = getTimeMilliseconds(); 

      char filePath[512]; 
      sprintf(filePath, "%s/%s", argv[1], entries[e]->d_name);

      static double totalProcTime = 0; 
      double perFileProcTime = (e > eStart) ? (totalProcTime / (e - eStart)) : 0; 
      printf("\rProcessing file %s [%04d/%04d] (Avg Proc Time = %lf ms)",
             filePath, (e - eStart), (eEnd - eStart), perFileProcTime); 
      fflush(stdout);

      char pcapErrorMsg[PCAP_ERRBUF_SIZE] = { 0 };
      pcap_t *pcap = pcap_open_offline(filePath, pcapErrorMsg);
      if(pcap == NULL) {
        fprintf(stderr, "Could not open '%s' with pcap - %s\n", filePath,
                pcapErrorMsg);
        exit(1);
      }

      struct bpf_program bpf;
      if(pcap_compile(pcap, &bpf, "udp port 53 and (dst host " OLD_ADDRESS_STR
                      " or dst host " NEW_ADDRESS_STR " or src host "
                      OLD_ADDRESS_STR " or src host " NEW_ADDRESS_STR ")",
                      1, 0) < 0) {
        fprintf(stderr, "Could not compile filter - %s\n", pcap_geterr(pcap));
        exit(1);
      }
      if(pcap_setfilter(pcap, &bpf) < 0) {
        fprintf(stderr, "Could not set filter - %s\n", pcap_geterr(pcap));
        exit(1);
      }
      pcap_freecode(&bpf);

      int datalinkType = pcap_datalink(pcap);

      int datalinkOffset;
      switch(datalinkType) {
        case DLT_LINUX_SLL:
          datalinkOffset = 16;
          break;
        case DLT_EN10MB:
          datalinkOffset = 14;
          break;
        case DLT_IEEE802:
          datalinkOffset = 22;
          break;
        case DLT_NULL:
          datalinkOffset = 4;
          break;
        case DLT_SLIP:
        case DLT_PPP:
          datalinkOffset = 24;
          break;
        case DLT_RAW:
          datalinkOffset = 0;
          break;
        default:
          fprintf(stderr, "Unknown datalink type %d\n", datalinkType);
          exit(1);
      }

      isFirstCapturePacket = true;

      if(pcap_loop(pcap, -1, handlePacket, (uint8_t *)&datalinkOffset) < 0) {
        fprintf(stderr, "Call to pcap_loop() failed - %s\n", pcap_geterr(pcap));
        exit(1);
      }

      // Going through the list to check if we can process any more packets, with
      // the relaxed ordering constraint now that we have no more to add/pair
      while(packetProc < packetAdd) {
        if(packets[packetProc].ready) {
          processQueryResponse(&packets[packetProc]);
        }
        packetProc++;
      }
      packetAdd = 0;
      packetProc = 0;

      // Keeping track of captured time
      isFirstCapture = false;
      lastCaptureTime = (captureLastTime - captureStartTime);
      totalCaptureTime += lastCaptureTime;
      fprintf(capturelenLog, "%lu\n", lastCaptureTime);

      uint64_t endProcTime = getTimeMilliseconds();
      totalProcTime += (endProcTime - startProcTime);

      numEntriesParsed++;
      pcap_close(pcap);
    }

    free(entries[e]);
  }

  free(entries);

  printf("\n");

  endAllAnalysis();

  fclose(capturelenLog);
}

