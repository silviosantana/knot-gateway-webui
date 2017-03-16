var connect = require('connect');
var passport = require('passport');
var LocalStrategy = require('passport-local');
var jwt = require('jsonwebtoken');
var expressJwt = require('express-jwt');
var users = require('../models/users');
var bCrypt = require('bcrypt-nodejs');
var request = require('request');
var cloudConfig = require('../models/cloud');

var TOKEN_SECRET = require('../config').TOKEN_SECRET;
var TOKEN_EXPIRATION = require('../config').TOKEN_EXPIRATION;

var isValidPassword = function (user, password) {
  return bCrypt.compareSync(password, user.password);
};

var initialize = function initialize() {
  return passport.initialize();
};

var createToken = function createToken(req, res, next) {
  req.token = jwt.sign(req.user, TOKEN_SECRET, { expiresIn: TOKEN_EXPIRATION });
  next();
};

var respond = function respond(req, res) {
  res.json({
    user: req.user,
    token: req.token
  });
};

var verifyUserOnCloud = function (cloud, email, done) {
  request({
    url: 'http://' + cloud.servername + ':' + cloud.port + '/devices/user',
    method: 'GET',
    headers: {
      meshblu_auth_email: email
    }
  }, function (err, response, body) {
    var data = {};
    var result;
    if (body) {
      result = JSON.parse(body);
    }
    if (err) {
      console.log('Error retrieving user from cloud: ' + err);
      err.status = 500;
      done(err, null);
    } else if (!result.email) {
      err = {};
      console.log('User not found');
      err.status = 500;
      done(err, null);
    } else {
      data.email = result.email;
      done(null, data);
    }
  });
};

var signinOnCloud = function signinOnCloud(req, res) {
  cloudConfig.getCloudSettings(function onCloudSettingsSet(err, cloud) {
    if (err || !cloud) {
      res.sendStatus(400);
    } else {
      verifyUserOnCloud(cloud, req.body.email, function (error, result) {
        if (error) {
          res.sendStatus(error.status);
        } else {
          res.status(409).send(result);
        }
      });
    }
  });
};

var checkDatabase = function checkDatabase(req, res, next) {
  users.isEmpty(function (err, empty) {
    if (err) {
      return err;
    } else if (empty) {
      signinOnCloud(req, res);
    } else {
      next();
    }
    return null;
  });
};

var authenticate = function authenticate() {
  var chain = connect();
  chain.use(checkDatabase);
  chain.use(passport.authenticate('local', { session: false }));
  chain.use(createToken);
  chain.use(respond);
  return chain;
};

var authorize = function authorize() {
  return expressJwt({ secret: TOKEN_SECRET });
};

// Configure passport
passport.use(new LocalStrategy({ usernameField: 'email' },
  function (email, password, done) {
    users.getUserByEmail(email, function onUserReturned(err, user) {
      if (err) {
        return done(err);
      } else if (!user || email !== user.email || !isValidPassword(user, password)) {
        return done(null, false);
      }

      // Currently there is only the admin user
      return done(null, { role: 'admin', uuid: user.uuid });
    });
  }
));

module.exports = {
  initialize: initialize,
  authenticate: authenticate,
  authorize: authorize
};
