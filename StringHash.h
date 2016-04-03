#ifndef STRINGHASH_H
#define STRINGHASH_H

#include <stdint.h>

#include "SipHash.h"

struct StringEqual {
  bool operator()(const char *s1, const char *s2) const {
    return (s1 == s2) || (s1 && s2 && strcmp(s1, s2) == 0);
  }
};

template<const uint8_t *key>
struct StringHash {
  size_t operator()(const char *s) const {
    if(s == NULL) {
      return 0;
    }

    return siphash_digest(key, (const uint8_t *) s, strlen(s));
  }
};

#endif // STRINGHASH_H

