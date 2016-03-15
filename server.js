'use strict';

var vogels = require('./model/vogels.js');
var User = require('./model/vogels.js').User;
var Transaction = require('./model/vogels.js').Transaction;
var Account = require('./model/vogels.js').Account;


var AWS = require('aws-sdk');
var express = require('express');  
var morgan = require('morgan');
var bodyParser = require('body-parser');
var session = require('express-session');
var C = require('./secret/credentials.json');
var uuid = require('uuid');
var crypto = require('crypto');
var bluebird = require('bluebird');
var bcrypt = bluebird.promisifyAll(require('bcrypt'));
var passport = require('passport');
var FacebookStrategy = require('passport-facebook').Strategy;
var LocalStrategy = require('passport-local').Strategy;

var app = express();

var RedisStore = require('connect-redis')(session);

//Configure AWS
AWS.config.update({region : C.AWS.REGION, accessKeyId: C.AWS.ACCESSKEY, secretAccessKey: C.AWS.SECRET});

//Grab Dynamo Database
var database = new AWS.DynamoDB();
 
//We make a new session but set the client as the Elasticache Server (instead of a local redis server on the EC2)
app.use(session({
    resave : false,
    saveUninitialized: false,
    secret : C.APP.SESSIONSECRET, //Cookie Secret that identifies session
    store : new RedisStore()
}));

//Log all requests to application with Morgan
app.use(morgan('dev'));
app.disable('etag');

//parse JSON in the request body
app.use(bodyParser.urlencoded({
  extended: true
}));


// //Returns the current user saved in the session.user variable
app.get('/getCurrentUser', function(req, res) {
    
    if (session.user !== undefined) {
        //set email hash for gravitar lookup
        session.user.imageHash = crypto.createHash('md5').update(session.user.email).digest('hex');
        res.send(session.user);
        
    } else {
        res.send({username : "please login again."});  
    }
});

app.post('/updateUser', function(req, res) {
    
    console.log("Body " + JSON.stringify(req.body));
    console.log(JSON.stringify(session.user));
    
    //if this user has a new email to add
    var newEmail = session.user.email;
    
    if (req.body.email !== undefined && req.body.email.length > 0) {
        newEmail = req.body.email;
    }
    
    console.log("Email: " + newEmail);
        
        //grab password
        var newPassword = session.user.password;
        
        //if the password typed is the users password, auth to change it
        if (newPassword === req.body.currentPassword && req.body.newPassword === req.body.newPasswordConfirm) {
            newPassword = req.body.newPassword;
        
            
            bcrypt.hashAsync(newPassword, 10)
                .then(function(hash) {
                    
                    User.create({
                        "email": newEmail,
                        "password": hash }  
                    , function(err, user) {
                        
                        if (err) {
                            console.log(err);
                        } else {
                            console.log("User changed: " + JSON.stringify(fullyUpdatedUser));
                            
                            var formattedUser = {

                                email: newEmail,
                                password: hash
                            }
                            
                            session.user = formattedUser;
                            res.redirect('/secure.html');
                        }
                        
                    });
                        
            }).catch(function(err) {
                console.log(err);
            });
        } else {
            
            var fullyUpdatedUser = {
                        
                        "email": newEmail,
                        "password": newPassword }  
                    }
                        
                    console.log(fullyUpdatedUser); 
                    
                     User.create(fullyUpdatedUser, function(err, user) {
                        if (err) {
                            console.log(err);
                        } else {
                            console.log("User changed: " + JSON.stringify(fullyUpdatedUser));
                            
                            var formattedUser = {
                                email: fullyUpdatedUser.email,
                                password: fullyUpdatedUser.password

                            }
                            
                            session.user = formattedUser;
                            res.redirect('/secure.html');
                        }
                    });   
        
         
});


//Configure Passport

var localStrategy = new LocalStrategy(function(email, password, done) {
    
   //code to validate that username and password are valid credentials
    
    User.get(email, function(err, user) {
        if (err) {
            console.log(err);
            done(null, false);
            
        } else {
            
           //console.log(user); 
           //If no user was returned from the query, fail local auth
           if (user.get('email') == undefined) {  
                return done(null, false);   
            } else {

                bcrypt.hashAsync(password, 10)
                .then(function(hash) {
                    return [hash, bcrypt.compareAsync(password, user.get('password'))];
                }).spread(function(hash, isSame) {
                        if (isSame) {
                            var userObject = { 
                                email : user.get('email'),
                                password: password
                            }    
                            
                            session.user = userObject;

                            console.log('Local Stratgey: ' + JSON.stringify(userObject));
                            return done(null, JSON.stringify(userObject)); 
                        } else {
                            
                            res.json({ message : "Email or Password incorrect."});
                            res.end();
                            return done(null, false);
                        }
                })
                .catch(function(err) { 
                    console.log(err);
                    return done(null, false);
                });
            }
        }
    })
});

var facebookStrategy = new FacebookStrategy({
    clientID: C.FACEBOOK.CLIENTID,
    clientSecret: C.FACEBOOK.CLIENTSECRET,
    callbackURL: "http://ec2-54-173-99-96.compute-1.amazonaws.com/signin/facebook/callback"
  }, 
  
  function(accessToken, refreshToken, profile, cb) {
    addUser(profile, cb)
  });
  
//This function only adds new users to Dynamo, however if use exists it overwrites the data
var addUser = function(profile, cb) {
    
    console.log(profile);

    var newUser = {
        "email": profile.email,
        "password": uuid.v1()
    }
        
    User.create(newUser, function(err, user) {
        if (err) {
            console.log(err);
        } else {
        console.log("User added: " + JSON.stringify(newUser));
        
        var formattedUser = {
            email: newUser.email,
            password: newUser.password
        }
        
        session.user = formattedUser;
        
            return cb(err, data);
        }
        
    });    
};

//use the configured local strategy
passport.use(localStrategy);
passport.use(facebookStrategy);

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

app.use(passport.initialize());
app.use(passport.session());

//Load static files
app.use(express.static(__dirname + '/static/public'));                                                                                                                         

//Local sign up route, redirects to home if it can't find a user
app.post('/signin/local', function (req, res, next) {
    
  passport.authenticate('local', function(err, user, info) {
    if (err) {
      return next(err); // will generate a 500 error
    }
    // Generate a JSON response reflecting authentication status
    if (!user) {
      return res.redirect('/');
    }
    req.user = user;
    req.login(user, loginErr => {
      if (loginErr) {
        return next(loginErr);
      }
      return res.redirect('/secure.html');
    });      
  })(req, res, next);
    
});

//Facebook sign in route
app.get('/signin/facebook', passport.authenticate('facebook'));

//Facebook sign in callback
app.get('/signin/facebook/callback', passport.authenticate('facebook'), function(req, res) {
    res.redirect('/secure.html');
});

//Logout the current user and move them back to the home page                                                  
app.get('/signout', function(req, res) {
    req.logout();
    session.user = undefined; //reset custom user property
    res.redirect('/');
}); 

//Move the user to the signup page
app.get('/signup', function(req,res) {
   return res.redirect('/signup.html'); 
});


app.get('/secure', authenticate, function (req, res) {
    return res.redirect('/secure.html');
});

//will show you your accounts if you are logged in and they belong to you.
app.get('/accounts', authenticate, function(req, res) {
    
    var finalAccounts = [];
    Account.scan().where('owner').equals(session.user.email).exec(function(err, accounts) {
         if (err) {
            console.log('account lookup err: ', err);
        } else {
            var finalAccounts = [];
            
            for (var i = 0; i < accounts.Items.length; i++) {
                var fetchedAccount = accounts.Items[i];
                
                var formattedAccount = {
                    name : fetchedAccount.get('name'),
                    currentBalance : fetchedAccount.get('currentBalance'),
                    accountId : fetchedAccount.get('accountId')
                }
                
                finalAccounts.push(formattedAccount);
            }
        }
        console.log("User has " + finalAccounts.length + " Accounts");
        res.send(finalAccounts);
    });
});

//create a new account
app.post('/accounts/create', authenticate, function(req,res) {
    
    Account.scan().where('owner').equals(session.user.email).exec(function(err, accounts) {
        
        //respond with an err if you have 5 accounts
        if (accounts.Items.length >= 5) {
            res.status(400).json({message : "You can only have 5 accounts max"});
            return;
        }

        for (var i = 0; i < accounts.Items.length; i++) {
            //if you find an account with that name
            if (accounts.Items[i].get('name') == req.body.accountName) {
                res.status(400).json({ message : "You already have an account with that name" });
                return;
            } 
        }
        //make an account for this user, balance is 0 and the name is whatever's passed in under the req.body.accountName property
       Account.create({ "owner" : session.user.email, "currentBalance" : 0, "name" : req.body.accountName }, function(err, account) {
           res.status(200).json({message : "Account " + account.name + " created for" + account.owner });
           return;
       }); 
    });
    
});

app.post('/createUser', function(req, res) { 
    console.log(req.body);
    
    //if the password and confirm match, add user
    if (req.body.password === req.body.passwordConfirm) {
        
        bcrypt.hashAsync(req.body.password, 10)
            .then(function(hash) {

                User.create({"email": req.body.email, "password": hash}, 
                    function(err, user) {
                    
                    if (err) {
                        console.log(err);
                    } else {
                        //console.log("User added: " + JSON.stringify(data));
                            
                        Account.create({ 'name' : 'Primary', 'owner' : req.body.email, 'currentBalance' : 100}, function(err, account) {
                            if (err) {
                                console.log(err);
                                
                            } else {
                                console.log('default account created');
                            }
                        });
                                    
                        var formattedUser = {

                            email: req.body.email,
                            password: hash
                        }
                        
                        session.user = formattedUser;
    
                        req.login(formattedUser, function(err) {
                            if (err) { return next(err); }
                            return res.redirect('/secure.html');
                        });
                    }
                });
            });
        
    } else {
       res.send("Passwords don't match, try again!");
       res.end();
    }
    
});

app.delete('/account/:accountId', authenticate, function(req, res) {
    //if user is the owner of the account, delete it
    
    Account.scan().where('owner').equals(session.user.email).exec(function(err, accounts) {
        
        for (var i = 0; i < accounts.Items.length; i++) {
            var singleAccount = accounts.Items[i];
            if (singleAccount.get('name') == req.body.accountName && singleAccount.get('currentBalance') == 0 && singleAccount.get('name') != 'Primary') {
                Account.destroy(accounts.Items[i].get('accountId'), function(err) {
                     if (err) {
                        console.log("Error deleting account: " + err);
                        res.status(500).json({message: "deleted account fail " + err});
                    } else {
                        res.status(200).json({message: "deleted account successful"});
                        return;
                    }
                });
                
            } 
        }
        
    });
});

//creates a new transaction if it fits all the parameters
app.post('/transaction/create', authenticate, function(req, res) {
    
    var fromAccount; //must be your own account
    var toAccount; //any account from any user
    
    Account.scan().where('owner').equals(session.user.email).exec(function(err, accounts) {
        
        for (var i = 0; i < accounts.Items.length; i++) {
            
            var currentAccount = accounts.Items[i];
            
            if (currentAccount.get('name') == req.body.fromAccount) {
                fromAccount = currentAccount;
            }
            
            //your transfering money to an account you own
            if (req.body.toAccountEmail == session.user.email) {
                if (currentAccount.get('name') == req.body.toAccount) {
                    toAccount = currentAccount;
                }
            }

        }
        
        //if you don't have an account, respond with, you don't have an account of that name
        if (fromAccount == undefined) {
            res.status(400).json({ message : "You don't have an account named " + req.body.fromAccount});
            return;
        } 
        
        //if you aren't transfering money to an account you own, go find the account 
        if (toAccount == undefined) {
            Account.scan().where('owner').equals(req.body.toAccountEmail).exec(function(err, accounts) {
               
               for (var i = 0; i < accounts.Items.length; i++) {
                   var currentAccount = accounts.Items[i];
                   
                   if (currentAccount.get('name') == req.body.toAccount) {
                       toAccount == currentAccount;
                   } 
               }
               
               if (toAccount == undefined) {
                  res.status(400).json({ message : "That person doesn't have an account named " + req.body.toAccount}); 
                  return;
               } else {
                   //transfer money from your account to another person's
                   transferFunds(req, res, toAccount, fromAccount, req.body.sendAmount);
               } 
            });
            
            
        } else {
            //the account your transfer money to is your own, do so here!!
            transferFunds(req, res, toAccount, fromAccount, req.body.sendAmount);
        }
        
       
       //transactionId
       //sourceAccount 
       //destinationAccount 
       //reason 
        
    });  
});

function transferFunds(req, res, toAccount, fromAccount, amount) {
    if (fromAccount.get('currentBalance') >= amount) { //if the account your transfering money from has enough to send
        
        //fromAccount update
        Account.update({accountId: fromAccount.accountId, owner: fromAccount.owner, currentBalance: fromAccount.currentBalance - amount }, function(err, account) {
            
            if (err) {
                res.send({message : err});
                return;
            }
            //toAccount update
            Account.update({accountId:toAccount.accountId ,owner: toAccount.owner, currentBalance:toAccount.currentBalance + amount }, function(err,account) {
                
                  if (err) {
                        res.send({message : err});
                        return;
                  }
                  Transaction.create({sourceAccount: fromAccount.accountId , destinationAccount: toAccount.accountId }, function(err, trans) {
                        res.status(200).json({message : "transfer complete & transaction created"});
                        return;  
                  });
            });
            
        });
    }    
};

//get all transactions, obscures all account numbers if they aren't yours
app.get('/transaction', function(req, res) {
    
    for (var i = 0; i < session.user.accounts.length; i++) {
        var myAccount = session.user.accounts[i];
        //Transaction.scan().where('sourceAccount').equals()
        
                 
         
        
        
    }
    
    //obscure numbers that aren't yours, only return twenty at a time
});

function getUserAccounts(req, res, next) {
    
    Account.scan().where('owner').equals(session.user.email).exec(function(err, accounts) {
         
         var myAccounts = [];
         
         for (var i = 0; i < accounts.Item.length; i++) {
             myAccounts.push(accounts.Item[i]);  
         }
         //add my user accounts to my session object
         session.user.accounts = myAccounts;
         next();
     });
}



//If user is logged in or not, redirect or keep walking down middleware chain
function authenticate(req, res, next) {
    
    if (req.isAuthenticated()) {
       return next();
    } 
    res.redirect('/');
}; 

app.use(authenticate);

app.use(express.static(__dirname + '/static/secure/'));

app.listen(80, function() {
    console.log('server is listening..');
});