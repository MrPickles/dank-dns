var fs = require('fs'),
    readline = require('readline');

var reader = readline.createInterface({
  input : fs.createReadStream('./validTLDs.txt')
});

var TLDs = [];

reader.on('line', function(line) {
  var matches = line.match(/validTLDs\.insert\("(.+)"\); validTLDs.insert\(".+"\);/);
  TLDs.push(matches[1]);
});
reader.on('close', function() {
  fs.writeFileSync('./validTLDs.json', JSON.stringify(TLDs, null, 2));
})
