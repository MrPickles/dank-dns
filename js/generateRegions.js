var fs = require('fs'),
    readline = require('readline'),
    path = require('path'),
    async = require('async'),
    timezoner = require('timezoner');

if (!process.argv[2]) {
  console.error('usage: node %s <regions.tsv path>', path.basename(process.argv[1]));
  process.exit(1);
}

var fileStat = fs.statSync(process.argv[2]);
if (!fileStat.isFile()) {
  console.error('[Error] %s is not a valid path', process.argv[2]);
  process.exit(1);
}

var reader = readline.createInterface({
  input : fs.createReadStream(process.argv[2])
});

var header;
var regions = {};
reader.on('line', function(line) {
  if (header === undefined) {
    // parse header
    var headerArr = line.split('\t');
    header = {};
    for (var i = 0; i < headerArr.length; i++) {
      header[headerArr[i]] = i;
    }
  } else {
    var fields = line.split('\t');
    var abbreviation = fields[header['abbreviation']];
    var lat = fields[header['lat']];
    var lon = fields[header['lon']];
    regions[abbreviation] = {
      lat : parseFloat(lat),
      lon : parseFloat(lon),
      timezoneId : null,
      timezoneName : null
    }
  }
});

reader.on('close', function() {
  async.each(
    Object.keys(regions), 
    function(abbrv, d) {
      console.log(abbrv);
      var timezone = timezoner.getTimeZone(
        regions[abbrv].lat,
        regions[abbrv].lon,
        function(err, data) {
          if (err) {
            console.log(regions[abbrv], abbrv);
            throw new Error(err);
          } else {
            regions[abbrv].timezoneId = data.timeZoneId;
            regions[abbrv].timezoneName = data.timeZoneName;
            d();
          }
        },
        {key : 'AIzaSyAHLiZ3Q7t-TEdhiHelR2iVMQKe2knlcpo'}
      );
    },
    function(err) {
      fs.writeFileSync(path.resolve(__dirname, 'regions.json'), JSON.stringify(regions, null, 2));
    }
  );
});
