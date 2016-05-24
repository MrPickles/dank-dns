#ifndef CONFIG_H
#define CONFIG_H

// MongoDB details
#define MONGODB_URL "mongodb://localhost:27017"
#define MONGODB_DB_NAME "ctest"
#define MONGODB_COLLECTION "test"
#define MONGODB_INSERT_CACHE 10000

/* set this value to zero to avoid saving to the database */
#define USE_MONGODB 1

#endif

