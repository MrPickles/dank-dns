#ifndef CONFIG_H
#define CONFIG_H

#include <netinet/ip.h>

////////////////////////////////////////////////////////////////////////////////
// Macros

#define IPV4_OCTETS(a,b,c,d) (((uint32_t)a)<<24|((uint32_t)b)<<16| \
                             ((uint32_t)c)<<8|((uint32_t)d))

#define TIME_S2US(t) ((uint64_t)(t) * 1000000)
#define TIME_US2S(t) ((uint64_t)(t) / 1000000.0)
#define TIME_S2MS(t) ((uint64_t)(t) * 1000)

////////////////////////////////////////////////////////////////////////////////
// Configuration - General Information

#define OLD_ADDRESS_STR       "128.8.10.90"
#define OLD_ADDRESS           IPV4_OCTETS(128,8,10,90)

#define NEW_ADDRESS_STR       "199.7.91.13"
#define NEW_ADDRESS           IPV4_OCTETS(199,7,91,13)

// Old server sent out its first response containing an A record for the new
// IP address at exactly 09:53:01 on 01/03/2013 local time.
#define TIME_OLD_ADVERT_NEW   TIME_S2US(1357224781)

// New server has been online since before the trace has started, so just
// setting this time to 0
#define TIME_NEW_ONLINE       TIME_S2US(0)

////////////////////////////////////////////////////////////////////////////////
// Configuration - DNS Information

#define OBSOLETE_TYPES_VALID 1
#define EXPERIMENTAL_TYPES_VALID 1

////////////////////////////////////////////////////////////////////////////////
// Configuration - Analysis

#define QPS_MAX_TYPES 10
#define SCS_OLD_UNIQUE_THRESHOLD 3

#endif // CONFIG_H

