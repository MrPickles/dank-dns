'use strict';

var mongoose = require('mongoose'),
    Schema = mongoose.Schema,
    ObjectId = Schema.ObjectId,
    async = require('async');

var DNSSchema = {
  node : {
    type : String,
    index : true,
    required : true
  },
  time : {
    type : Date,
    index : true,
    required : true
  },
  reqIP : {
    type : Buffer,
    index : true,
    required : true
  },
  resIP : {
    type : Buffer,
    index : true,
    required : true
  },
  header : {
    aa : { // authoritative answer
      type : Boolean,
      required : true
    },
    tc : { // truncation flag
      type : Boolean, 
      required : true
    },
    rd : { // recursion desired
      type : Boolean,
      required : true
    },
    ra : { // recursion available
      type : Boolean,
      required : true
    },
    rc : { // response code
      type : Number, 
      required : true
    }
  },
  question : [{
    name : {
      type : String,
      index : true
    },
    type : {
      type : Number,
      index : true,
      required : true
    },
    class : {
      type : Number,
      index : true,
      required : true
    }
  }],
  DNSSEC : { // if edns.type === 0x29 || edns.z === 0x8000
    type : Boolean,
    required : true,
    default : false
  },
  answerCount : {
    type : Number,
    required : true
  },
  authorityCount : {
    type : Number,
    required : true
  },
  additionalCount : {
    type : Number,
    required : true
  }
};

var DNS = mongoose.model('DNS', DNSSchema);
