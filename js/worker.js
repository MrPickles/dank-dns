var mongoose = require('mongoose'),
    path = require('path'),
    pcap = require('parse-pcap'),
    dnsParser = require('native-dns-packet');

var chalk = require('chalk');

// load Mongoose model
require('./models/DNS');
var DNSPacket = mongoose.model('DNS');

var i = 0;
process.on('message', function(msg) {
  if (msg.reap) {
    process.exit();
  } else if (msg.filename) {
    processPCAP(msg.filename);
    process.send('finished');
  }
});

function processPCAP(filename) {
  var analyzer = new pcap(filename);
  console.log(chalk.blue('starting %s'), path.basename(filename));
  analyzer.packets.forEach(function(packet) {
    var IPPacket = packet.data.slice(14); // ethernet header is 14 bytes
    var srcIP = IPPacket.slice(12, 16);
    var dstIP = IPPacket.slice(16, 20);
    var IPProtocol = IPPacket.slice(9, 10); // Proto 17 is UDP, Proto 6 is TCP
    if (IPProtocol.readInt8() === 17) {
      var UDPPacket = IPPacket.slice(20); // ip header is 20 bytes
      var srcPort = UDPPacket.slice(0,2);
      var dstPort = UDPPacket.slice(2,4);
      var DNSData = UDPPacket.slice(8); // UDP header is 8 bytes
      if (srcPort.readUInt16BE() === 53 || dstPort.readUInt16BE() === 53) {

        try {
          var parsedDNSData = dnsParser.parse(DNSData);
        } catch(err) {
          // console.log('file: %s | packet %d', path.basename(filename), counter); //malformed packets
        }
        /*
        console.log(chalk.blue('--------------------------------- Packet %d ---------------------------------'), i);
        console.log(chalk.yellow('Source: %s.%s.%s.%s:%d'), srcIP[0], srcIP[1], srcIP[2], srcIP[3], srcPort.readUInt16BE());
        console.log(chalk.magenta('Destination: %s.%s.%s.%s:%d'), dstIP[0], dstIP[1], dstIP[2], dstIP[3], dstPort.readUInt16BE());
        */
        //console.log(chalk.white(JSON.stringify(parsedDNSData, null, 2)));
      }
    }
  });
  console.log(chalk.green('finished %s'), path.basename(filename));
}
