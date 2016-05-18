#ifndef DB_H
#define DB_H

#include "dns.h"

#define MONGODB_URL "mongodb://localhost:27017"
#define MONGODB_DB_NAME "dnsc"
#define MONGODB_COLLECTION "dns"
#define MONGODB_INSERT_CACHE 1000

/* set this value to zero to avoid saving to the databse */
#define USE_MONGODB 1

/* 
 * Sets up the connection to the database
 */
void connectToDB();

/*
 * Cache the inserts and then bulk insert when a treshold's met
 */
void insertIntoDB(dns_t *dns);

/*
 * Disconnect from the DB, insert any still cached inserts
 */
void disconnectDB();

#endif
