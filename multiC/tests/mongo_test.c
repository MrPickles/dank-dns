#include <bson.h>
#include <bcon.h>
#include <mongoc.h>

#include "test.h"

int main (int argc, char *argv[]) {
  print_section("Mongo Connectivity Test");

  mongoc_client_t *client;
  mongoc_database_t *database;
  mongoc_collection_t *collection;
  bson_t *command, reply, *insert;
  bson_error_t error;
  char *str;
  bool retval;

  /*
   * Required to initialize libmongoc's internals
   */
  mongoc_init();

  /*
   * Create a new client instance
   */
  client = mongoc_client_new("mongodb://localhost:27017");

  /*
   * Get a handle on the database "db_name" and collection "coll_name"
   */
  database = mongoc_client_get_database(client, "db_name");
  collection = mongoc_client_get_collection(client, "db_name", "coll_name");

  /*
   * Do work. This example pings the database, prints the result as JSON and
   * performs an insert
   */
  command = BCON_NEW("ping", BCON_INT32(1));

  retval = mongoc_client_command_simple(client, "admin", command,
      NULL, &reply, &error);

  if (!retval) {
    fprintf(stderr, ANSI_COLOR_RED "%s\n" ANSI_COLOR_RESET, error.message);
  }
  print_state("Can ping MongoDB", retval);

  str = bson_as_json(&reply, NULL);
  print_state("Mongo ping reply approved", !strcmp(str, "{ \"ok\" : 1 }"));

  insert = BCON_NEW("hello", BCON_UTF8 ("world"));

  if (!mongoc_collection_insert(collection, MONGOC_INSERT_NONE,
        insert, NULL, &error)) {
    print_state("Mongo inserts collection", 0);
    fprintf(stderr, ANSI_COLOR_RED "%s\n" ANSI_COLOR_RESET, error.message);
  } else {
    print_state("Mongo inserts collection", 1);
  }

  bson_destroy(insert);
  bson_destroy(&reply);
  bson_destroy(command);
  bson_free(str);

  /*
   * Release our handles and clean up libmongoc
   */
  mongoc_collection_destroy(collection);
  mongoc_database_destroy(database);
  mongoc_client_destroy(client);
  mongoc_cleanup();

  return 0;
}
