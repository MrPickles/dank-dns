'use strict';

var utils = require('./utils.js');
var async = require('async');
var db;
var collection;

var start = new Date('2016-03-08 00:00:00');
var stop = new Date('2016-03-08 23:59:59');

var nodes = [ 
  'cpmd'
];

var limit = 25;

var timeStart;
var timeStop;

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
        reqIP : '$reqIP'
      } },
      { $group : {
        _id : '$reqIP',
        total : { $sum : 1 }
      } },
      { $sort : {
        total : -1
      } }, 
      { $limit : limit }
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

