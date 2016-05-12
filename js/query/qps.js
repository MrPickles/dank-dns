'use strict';

var MongoClient = require('mongodb').MongoClient;
var async = require('async');
var utils = require('./utils.js');
var db;
var collection;

var minute = 60;
var hour = minute * 60;
var day = hour * 24;

var start = new Date('2016-03-08 11:00:00');
var stop = new Date('2016-03-08 13:00:00');

/*
var start = new Date('2016-03-08T11:00:34.060Z');
var stop = new Date('2016-03-08T13:00:34.728Z');
*/

var sizeInterval = 10;
var nodes = [
  'cpmd',
];

var timeStart;
var timeStop;

async.waterfall([
  function(d) {
    MongoClient.connect('mongodb://localhost/dns', function(err, dbctx) {
      collection = dbctx.collection('dns');
      db = dbctx;
      d(err);
    });
  },
  function(d) {
    console.log('Starting');
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
        node : 1,
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
        /*
        _id : { 
          time : '$time',
          node : '$node'
        },
        */
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
//        time : 1
        _id : 1
      } }
    ], function(err, results) {
      timeStop = new Date();
      console.log(results);
      console.log(timeStop - timeStart, 'ms');
      d(err);
    });
  },
], function(err) {
  db.close();
  console.log('Complete');
});


