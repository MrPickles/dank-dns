var async = require('async');
var utils = require('./utils.js');
var db;
var collection;

var start = new Date('2016-03-25 11:00:00');
var stop = new Date('2016-03-25 12:00:00');

var nodes = [
  'cpmd'
];
nodes = null;

var sender = '170.252.160.46';

var timeStart;
var timeStop;

var limit = 25;

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
      console.log(timeStop - timeStart, 'ms');
      d(err);
    });
  }
], function(err) {
  db.close();
  console.log('Complete');
});

