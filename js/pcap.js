#!/usr/bin/env node
'use strict';

var path = require('path'),
    fs = require('fs'),
    os = require('os'),
    child_process = require('child_process'),
    moment = require('moment'),
    cmdLineArgs = require('command-line-args');

var chalk = require('chalk');

var cli = cmdLineArgs([
  { name : 'directory', alias : 'd', type : String, multiple : true },
  { name : 'workers', alias : 'w', type : Number, defaultValue : os.cpus().length },
]);

var options = cli.parse();

// check if capture directory is present
if (!options.directory) {
  console.error('usage: node %s -d <capture dir> -w [# of workers]', path.basename(process.argv[1]));
  process.exit(1);
}

var workers = options.workers;
if (isNaN(workers)) {
  console.error(chalk.red('[Error] Worker number is invalid'));
  process.exit(1);
}

try {
  if (!fs.statSync(path.resolve(__dirname, 'tools/regions.json')).isFile()) {
    console.error(chalk.red('[Error] Run tools/generateRegion.js first to create regions.json'));
    process.exit(1);
  }
} catch (err) {
  console.error(chalk.red('[Error] Run tools/generateRegion.js first to create regions.json'));
  process.exit(1);
}

var regions = require('./tools/regions.json');

var jobs = [];
options.directory.forEach(function(directory) {
  fs.readdirSync(directory).forEach(function(file) {
    jobs.push(path.resolve(directory, file));
  });
});

if (jobs.length < workers) {
  workers = jobs.length; // if lesser workers processes are required
}

console.log(chalk.white('[Info] Spawning %d workers for a job queue of %d'), workers, jobs.length);
var totalPacketsProcessed = 0;
var totalMalformedPackets = 0;

var totalResponsePackets = 0;

function dispatchJob(worker) {
  if (jobs.length > 0) {
    var job = jobs.pop();
    var filenameParse = job.match(/pcap\.(....)\.(\d{10})/);
    var region = filenameParse[1];
    var timezoneId = regions[region].timezoneId;
    worker.send({
      filename : job,
      region : region,
      timezoneId : timezoneId
    });
    console.log(chalk.white('[Info] Sent job [%s] to worker #%d   \t| jobs left: %d'), path.basename(job), worker.workerID, jobs.length);
  } else {
    worker.send({
      reap : true
    });
  }
};

var workersArr = new Array(workers);

var startTime = new Date();
var endTime;

for (var i = 1; i <= workers; i++) {
  (function(i) {
    var worker = child_process.fork(path.resolve(__dirname, 'worker'));
    worker.workerID = i;
    worker.on('exit', function() {
      var status = chalk.white('[Info] Worker ' + i + ' exited   \t');
      workersArr.forEach(function(w) {
        if (w.connected) {
          status += chalk.green(w.workerID + ' ');
        } else {
          status += chalk.red(w.workerID + ' ');
        }
      });
      console.log(status);
    });
    worker.on('message', function(msg) {
      if (msg.ready) { // initial wait for DB connection
        dispatchJob(worker);
      } else if (msg.finished) { // worker finished a job
        console.log(chalk.green('[Debug] Worker #%d finished processing %d packets from %s | %d packets were malformed'), i, msg.packets, path.basename(msg.filename), msg.malformed)
        totalPacketsProcessed += msg.packets;
        totalMalformedPackets += msg.malformed;
        totalResponsePackets += msg.response;
        dispatchJob(worker);
      } else if (msg.duplicate) {
        console.log(chalk.yellow('[Warning] Duplicate entry in database, skipping file: %s'), msg.filename);
        dispatchJob(worker);
      }
    });
    workersArr[i] = worker;
  })(i);
}
process.on('exit', function() {
  endTime = new Date();
  console.log(chalk.blue('[Result] Total | Packets processed: %d | Response packets: %d | Malformed packets: %d'), totalPacketsProcessed, totalResponsePackets, totalMalformedPackets);
  console.log(chalk.white('[Info] Processing time: %d minutes'), moment.duration(endTime - startTime).asMinutes());
});

var firstSigInt = true;
process.on('SIGINT', function() {
  if (firstSigInt) {
    jobs = []; // clear job queue, wait for workers to end
    firstSigInt = false;
    console.log(chalk.yellow('[Warning] ctrl+c detected, clearing work queue and gracefully waiting for workers to finish'));
    return false;
  } else {
    process.exit(1);
  }
});
