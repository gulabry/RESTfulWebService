'use strict';

var C = require('../secret/credentials.json')
var vogels = require('vogels');
var joi = require('joi');
var Promise = require('bluebird');


vogels.AWS.config.update({
    credentials: {
        accessKeyId: C.AWS.ACCESSKEY,
        secretAccessKey: C.AWS.SECRET
    },
    region: C.AWS.REGION
});

vogels.User = vogels.define('user', {
   hashKey : 'email',
   timestamps: true,
   schema : {
       email : joi.string().email(),
       password : joi.string()
   }
    
});

vogels.Account = vogels.define('account', {
   hashKey : 'accountId',
   rangeKey : 'owner',
   timestamps : true,
   schema : {
      accountId : vogels.types.uuid(),
      name : joi.string(),
      owner : joi.string().email(),
      currentBalance : joi.number() 
   } 
   
});

vogels.Transaction = vogels.define('transaction', {
   hashKey : 'transactionId',
   timestamps : true,
   schema : {
       transactionId : vogels.types.uuid(),
       sourceAccount : joi.string(),
       destinationAccount : joi.string(),
       reason : joi.string()
   } 
});

vogels.createTables(function(err) {
  if (err) {
    console.log('Error creating tables: ', err);
  } else {
    console.log('Tables has been created');
  }
});

module.exports = vogels;

