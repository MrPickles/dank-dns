'use strict';

var mongoose = require('mongoose'),
    path = require('path'),
    fs = require('fs'),
    zlib = require('zlib'),
    pcap = require('pcap-parser'),
    dnsParser = require('native-dns-packet'),
    moment = require('moment-timezone');

var cacheSize = 1000;
/*
// load Mongoose model
require('./models/DNS');
var DNSModel = mongoose.model('DNS'); // load db model

mongoose.connect('mongodb://localhost/dns'); // open db connection
mongoose.connection.on('error', console.log);
*/
var collection;
var MongoClient = require('mongodb').MongoClient;
var dbConnection;
MongoClient.connect('mongodb://localhost/dns', function(err, dbctx) {
  collection = dbctx.collection('dns');
  dbConnection = dbctx;
  process.send({ready : true});
});

process.on('message', function(msg) {
  if (msg.reap) {
    // Need to disconnect DB
    dbConnection.close(function() {
      process.exit();
    });
  } else if (msg.filename) {
    processPCAP(msg.filename, msg.timezoneId, msg.region);
  }
});


var i = 0;


function processPCAP(filename, timezoneId, region) {
  // Open file stream for decompression
  var fileStream = fs.createReadStream(filename);
  var decompressor = zlib.createGunzip();
  fileStream.pipe(decompressor);

  // pcap analysis
  var analyzer = new pcap.parse(decompressor);
  var processedPackets = 0;
  var malformedPackets = 0;

  var insertCache = new Array(cacheSize);
  var currInsertCacheIndex = 0;
  var inserted = 0;

  var bulkInsert = function(arr) {
    collection.insert(arr, function(err) {
      if (err) {
        console.log(err);
      }
      inserted += arr.length;
    });
  };

  var responsePackets = 0;
  analyzer.on('packet', function(packet) {
    var packetDate = moment.tz((packet.header.timestampSeconds * 1000) + (packet.header.timestampMicroseconds / 1000), timezoneId);
    //console.log(filename, packetDate.toString());
    var IPPacket = packet.data.slice(14); // ethernet header is 14 bytes
    var srcIP = IPPacket.slice(12, 16);
    var dstIP = IPPacket.slice(16, 20);
    var IPProtocol = IPPacket.slice(9, 10); // Proto 17 is UDP, Proto 6 is TCP
    if (IPProtocol.readInt8() === 17) {
      var UDPPacket = IPPacket.slice(20); // ip header is 20 bytes
      var srcPort = UDPPacket.slice(0,2);
      var dstPort = UDPPacket.slice(2,4);
      var DNSData = UDPPacket.slice(8); // UDP header is 8 bytes
      if (srcPort.readUInt16BE() === 53 || dstPort.readUInt16BE() === 53) { // if DNS port
        try {
          var parsedDNSData = dnsParser.parse(DNSData);
          if (parsedDNSData.header.qr === 1) { // is response, only saving response for now
            responsePackets++;

            // check if DNSSEC
            var DNSSEC = false;
            if (parsedDNSData.edns) {
              DNSSEC = parsedDNSData.edns.type === 0x29 || parsedDNSData.edns.z === 0x8000;
            } else if (parsedDNSData.edns_options) {
              DNSSEC = parsedDNSData.edns_options.type === 0x29 || parsedDNSData.edns_options.z === 0x8000;
            }

            // form db entry
            var dns = {
              node : region,
              time : new Date(packetDate.valueOf()),
              reqIP : dstIP,
              resIP : srcIP,
              header : {
                aa : parsedDNSData.header.aa,
                tc : parsedDNSData.header.tc,
                rd : parsedDNSData.header.rd,
                ra : parsedDNSData.header.ra,
                rc : parsedDNSData.header.rcode
              },
              question : parsedDNSData.question,
              DNSSEC : DNSSEC,
              answerCount : parsedDNSData.answer.length,
              authorityCount : parsedDNSData.authority.length,
              additionalCount : parsedDNSData.additional.length
            };
            insertCache[currInsertCacheIndex] = dns;
            currInsertCacheIndex++;

            // if ready for bulk insert
            if (currInsertCacheIndex === cacheSize) {
              currInsertCacheIndex = 0;
              bulkInsert(insertCache);
            }
          }
          processedPackets++;
        } catch(err) {
          malformedPackets++;
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
  analyzer.on('end', function() {
    // Final insert
    if (currInsertCacheIndex > 0) {
      bulkInsert(insertCache.slice(0, currInsertCacheIndex));
    }
    
    // wait for mongo to finish
    var intervalID = setInterval(function() {
      if (inserted >= responsePackets) {
        clearInterval(intervalID);

        // ready to request another one
        process.send({
          finished : true,
          filename : filename,
          packets : processedPackets,
          response : responsePackets,
          malformed : malformedPackets
        });

      }
    }, 100);
  });

}

