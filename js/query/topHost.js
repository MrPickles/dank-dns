#!/usr/bin/env node
'use strict';

var async = require('async'),
    utils = require('./utils.js'),
    moment = require('moment'),
    cmdLineArgs = require('command-line-args');

var cli = cmdLineArgs([
  { name : 'start', alias : 's', description : 'Start time of query "YYYY-MM-DD HH:MM:SS"', type : String },
  { name : 'end', alias : 'e', description : 'End time of query "YYYY-MM-DD HH:MM:SS"', type : String },
  { name : 'replicas', alias : 'r', description : 'List of replicas to query, leave blank to default to all replicas', type : String, multiple : true },
  { name : 'origin', alias : 'o', description : 'The IP address of the requesting entity', type : String },
  { name : 'limit', alias : 'n', description : 'Number of top hosts to display, default : 10', type : Number, defaultValue : 10 }
]);

var options = cli.parse();

if (!options.start || !options.end) {
  console.log(cli.getUsage());
  process.exit(1);
}

var start = new Date(options.start);
var stop = new Date(options.end);
var nodes = options.replicas;

if (stop < start) {
  console.log('[Error] End time is earlier than start time');
  process.exit(1);
}

var sender = options.origin;
var limit = options.limit;

if (isNaN(limit)) {
  console.log('[Error] The specified limit option is not a number');
  process.exit(1);
}

var db;
var collection;

var timeStart, timeStop; // timer

console.log('Querying DB from %s to %s for %s requesting to %s replica(s)', start, stop, sender ? sender : 'all IPs', nodes ? nodes : 'all');

async.waterfall([
  function(d) {
    utils.connect(d);
  },
  function(conn, d) {
    console.log('Connected to DB');
    db = conn;
    collection = conn.collection('dns');
    timeStart = new Date();
    collection.aggregate([
      { $match : utils.cleanQuery({
        time : {
          $gte : start,
          $lte : stop
        },
        node : {
          $in : nodes
        },
        reqIp : sender
      }) },
      { $unwind : '$question' },
      { $project : {
        _id : { $toLower : '$question.name' }
      } },
      { $group : {
        _id : '$_id',
        total : { $sum : 1 }
      } },
      { $sort : {
        total : -1
      } },
      { $limit : limit }
    ], function(err, results) {
      timeStop = new Date();
      console.log(results);
      console.log('Query time: %d seconds', moment.duration(timeStop - timeStart).asSeconds()); 
      d(err);
    });
  }
], function(err) {
  db.close();
});

