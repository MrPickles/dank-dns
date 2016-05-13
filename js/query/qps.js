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
  { name : 'interval', alias : 'i', description : 'Number of minutes for each interval, default : 10', type : Number, defaultValue : 10 }
]);

var options = cli.parse();

if (!options.start || !options.end) {
  console.log(cli.getUsage());
  process.exit(1);
}

var start = new Date(options.start);
var stop = new Date(options.end);
var nodes = options.replicas;
var sizeInterval = parseInt(options.interval);

if (stop < start) {
  console.log('[Error] End time is earlier than start time');
  process.exit(1);
}

if (sizeInterval <= 0 || isNaN(sizeInterval)) {
  console.log('[Error] Invalid interval size');
  process.exit(1);
}

var db;
var collection;

var minute = 60;
var hour = minute * 60;
var day = hour * 24;

var timeStart, timeStop; // timer

console.log('Querying DB from %s to %s for QPS on %s replica(s) in %d minute intervals', start, stop, nodes ? nodes : 'all', sizeInterval);

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
        }
      }) },
      { $project : { 
        _id : 0,
        time : { 
          $add : [
            '$time',
            { $add : [
              // Lower ms to 0
              { $multiply : [
                -1,
                { $millisecond : '$time' }
              ] },

              // Lower s to 0
              { $multiply : [
                -1,
                1000,
                { $second : '$time' }
              ] },

              // Lower min to nextInterval in bucket
              { $multiply : [
                1000,
                60,
                { $subtract : [
                  sizeInterval,
                  { $mod : [
                    { $minute : '$time' },
                    sizeInterval
                  ] } 
                ] }
              ] }
            ] }
          ]
        }
      } },
      { $group : {
        _id : '$time',
        total : { $sum : 1 }
      } },
      { $project : {
        _id : 1,
        qps : { $divide : [ 
          '$total',
          sizeInterval
        ] }
      } },
      { $sort : {
        _id : 1
      } }
    ], function(err, results) {
      timeStop = new Date();
      console.log(results);
      console.log('Query time: %d seconds', moment.duration(timeStop - timeStart).asSeconds()); 
      d(err);
    });
  },
], function(err) {
  db.close();
});


