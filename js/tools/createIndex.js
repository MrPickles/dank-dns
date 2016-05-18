#!/usr/bin/env node
'use strict';

var MongoClient = require('mongodb').MongoClient,
    async = require('async'),
    config = require('../config');

var dbConnection, collection, filesCollection;

async.waterfall([
  function(d) {
    MongoClient.connect(config.db.url, function(err, dbctx) {
      dbConnection = dbctx;
      collection = dbctx.collection(config.db.collection);
      filesCollection = dbctx.collection(config.db.filesCollection);
      d(err);
    });
  },
  function(d) {
    collection.createIndex({ time : 1 }, function(err, result) {
      d(err);
    });
  },
  function(d) {
    collection.createIndex({ node : 1 }, function(err, result) {
      d(err);
    });
  },
  function(d) {
    collection.createIndex({ node : 1, time : 1, reqIP : 1 }, function(err, result) {
      d(err);
    });
  },
  function(d) {
    collection.createIndex({ reqIP : 1 }, function(err, result) {
      d(err);
    });
  },
  function(d) {
    filesCollection.createIndex({ filename : 1 }, function(err, result) {
      d(err);
    })
  }
], function(err) {
  if (err) {
    console.log('[Error] MongoDB Driver', err);
  } else {
    console.log('[Info] Indeces created');
  }
  dbConnection.close();
});
