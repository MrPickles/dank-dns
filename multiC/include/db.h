#ifndef DB_H
#define DB_H

#include "dns.h"

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
