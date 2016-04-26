/* imports */
var path = require('path'),
    fs = require('fs'),
    os = require('os'),
    cluster = require('cluster');

var chalk = require('chalk');

if (cluster.isMaster) {

  if (!process.argv[2]) {
    console.error('usage: node %s <capture dir> [# of workers]', path.basename(process.argv[1]));
    process.exit(1);
  }

  var workers = os.cpus().length;
  if (process.argv[3]) {
    workers = parseInt(process.argv[3]);
    if (isNaN(workers)) {
      console.error(chalk.red('[Error] Worker number is invalid'));
    }
  }

  var inputDir = path.resolve(process.argv[2]);
  var jobs = fs.readdirSync(inputDir).map(function(filename) {
    return path.resolve(inputDir, filename)
  });

  if (jobs.length < workers) {
    workers = jobs.length; // if lesser workers processes are required
  }

  console.log(chalk.white('[Info] Spawning %d workers for a job queue of %d'), workers, jobs.length);

  for (var i = 1; i <= workers; i++) {
    (function(i) {
      var worker = cluster.fork();
      var job = jobs.pop();
      worker.send({
        filename : job
      });
      worker.on('exit', function() {
        console.log(chalk.red('Worker %d exited'), i);
      });
      worker.on('message', function(msg) {
        if (msg === 'finished') { // worker finished a job
          if (jobs.length > 0) { // more jobs to process
            var anotherJob = jobs.pop();
            worker.send({
              filename : anotherJob
            });
          } else { // no more jobs
            worker.send({
              reap : true
            });
          }
        }
      });
    })(i);
  }
}

if (cluster.isWorker) {
  require('./worker');
}
