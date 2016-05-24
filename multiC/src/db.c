#include <bson.h>
#include <bcon.h>
#include <mongoc.h>

#include "config.h"
#include "util.h"
#include "db.h"

mongoc_client_t      *client;
mongoc_database_t    *database;
mongoc_collection_t  *collection;
mongoc_bulk_operation_t *bulk;
uint32_t currentDocIndex;

char *replica;

void connectToDB() {
#if USE_MONGODB == 1
  // required to init libmongoc's internals
  mongoc_init();

  // create new client instance
  client = mongoc_client_new(MONGODB_URL);

  // get a handle on the database and collection
  database = mongoc_client_get_database(client, MONGODB_DB_NAME);
  collection = mongoc_client_get_collection(client, MONGODB_DB_NAME, MONGODB_COLLECTION);
  bulk = mongoc_collection_create_bulk_operation(collection, true, NULL);
  currentDocIndex = 0;
#endif
}

void insertIntoDB(dns_t *dns) {
#if USE_MONGODB == 1
  uint64_t packetTime = (dns->packetTime.tv_sec * (uint64_t)1000) + (dns->packetTime.tv_usec / 1000);

  bson_t *doc, reply;
  bson_error_t error;
  bool retval;

  char reqIP[16] = {0};
  char resIP[16] = {0};

  inet_ntop(AF_INET, &dns->reqIP, reqIP, 16);
  inet_ntop(AF_INET, &dns->resIP, resIP, 16);

  if (dns->question.name == NULL) {
    dns->question.name = "";
  }

  doc = BCON_NEW(
          "node", BCON_UTF8(dns->replica),
          "time", BCON_DATE_TIME(packetTime),
          "reqIP", BCON_UTF8(reqIP),
          "resIP", BCON_UTF8(resIP),
          "aa", BCON_BOOL(dns->header.aa),
          "tc", BCON_BOOL(dns->header.tc),
          "rd", BCON_BOOL(dns->header.rd),
          "ra", BCON_BOOL(dns->header.ra),
          "rc", BCON_INT32(dns->header.rc),
          "question", "[",
            "{",
              "name", BCON_UTF8(dns->question.name),
              "type", BCON_INT32(dns->question.type),
              "class", BCON_INT32(dns->question.class),
            "}",
          "]",
          "DNSSEC", BCON_BOOL(dns->isDNSSEC),
          "questionCount", BCON_INT32(dns->header.qdcount),
          "answerCount", BCON_INT32(dns->header.ancount),
          "authorityCount", BCON_INT32(dns->header.nscount),
          "additionalCount", BCON_INT32(dns->header.arcount)
      );

  mongoc_bulk_operation_insert(bulk, doc);
  currentDocIndex++;

  if (currentDocIndex == MONGODB_INSERT_CACHE) {
    // execute the bulk operation
    retval = mongoc_bulk_operation_execute(bulk, &reply, &error);
    if (!retval) {
      fprintf(stderr, "[Error] MongoDB bulk operation: %s\n", error.message);
    }
    // reset bulk operation once done
    mongoc_bulk_operation_destroy(bulk);
    bulk = mongoc_collection_create_bulk_operation(collection, true, NULL);
    currentDocIndex = 0;
  }
#endif
}


void disconnectDB() {
#if USE_MONGODB == 1
  bson_t reply;
  bson_error_t error;
  bool retval;
  if (currentDocIndex != 0) {
    retval = mongoc_bulk_operation_execute(bulk, &reply, &error);
    if (!retval) {
      fprintf(stderr, "[Error] MongoDB bulk operation: %s\n", error.message);
    }
  }
  mongoc_collection_destroy(collection);
  mongoc_client_destroy(client);
  mongoc_cleanup();
#endif
}
