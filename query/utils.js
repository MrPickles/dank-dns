'use strict';

var lodash = require('lodash');
var MongoClient = require('mongodb').MongoClient;
var config = require('./config.js');
var validTLDs = require('./tools/validTLDs.json');

var helpers = {
  cleanQuery : function(query) {
    var result = { };

    if (query === null || query == undefined) {
      return query;
    } else if (query.constructor === Object) {
      Object.keys(query).forEach(function(key) {
        var temp = helpers.cleanQuery(query[key]);
        if (temp !== undefined && temp !== null) {
          if (temp.constructor === Object) {
            if (Object.keys(temp).length > 0) {
              result[key] = temp;
            }
          } else {
            result[key] = temp;
          }
        }
        return result;
      });
    } else {
      return query;
    }

    return result;
  },
  connect : function(cb) {
    MongoClient.connect(config.db.url, cb);
  },
  validTLDs : validTLDs,
  collection: config.db.collection
};

module.exports = helpers;


