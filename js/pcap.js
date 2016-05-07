var path = require('path'),
    fs = require('fs'),
    os = require('os'),
    child_process = require('child_process');

var chalk = require('chalk');

// check if capture directory is present
if (!process.argv[2]) {
  console.error('usage: node %s <capture dir> [# of workers]', path.basename(process.argv[1]));
  process.exit(1);
}

var workers = os.cpus().length;
if (process.argv[3]) {
  workers = parseInt(process.argv[3]);
  if (isNaN(workers)) {
    console.error(chalk.red('[Error] Worker number is invalid'));
    process.exit(1);
  }
}

if (!fs.statSync(path.resolve(__dirname, 'regions.json')).isFile()) {
  console.error(chalk.red('[Error] Run generateRegion.js first to create regions.json'));
  process.exit(1);
}

var regions = require('./regions.json');

var inputDir = path.resolve(process.argv[2]);
var jobs = fs.readdirSync(inputDir).map(function(filename) {
  return path.resolve(inputDir, filename)
});

if (jobs.length < workers) {
  workers = jobs.length; // if lesser workers processes are required
}

console.log(chalk.white('[Info] Spawning %d workers for a job queue of %d'), workers, jobs.length);
var totalPacketsProcessed = 0;
var totalMalformedPackets = 0;

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
    console.log(chalk.blue('Sent job [%s] to worker #%d | %d jobs left'), path.basename(job), i, jobs.length);
  } else {
    worker.send({
      reap : true
    });
  }
};

for (var i = 1; i <= workers; i++) {
  (function(i) {
    var worker = child_process.fork(path.resolve(__dirname, 'worker'));
    dispatchJob(worker);
    worker.on('exit', function() {
      console.log(chalk.red('Worker %d exited'), i);
    });
    worker.on('message', function(msg) {
      if (msg.finished) { // worker finished a job
        console.log(chalk.green('Worker #%d finished processing %d packets from %s | %d packets were malformed'), i, msg.packets, path.basename(msg.filename), msg.malformed)
        totalPacketsProcessed += msg.packets;
        totalMalformedPackets += msg.malformed;
        dispatchJob(worker);
      }
    });
  })(i);
}
process.on('exit', function() {
  console.log(chalk.green('Total packets processed: %d | Total malformed packets: %d'), totalPacketsProcessed, totalMalformedPackets);
});
