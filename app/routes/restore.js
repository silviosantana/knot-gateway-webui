var router = require('express').Router(); // eslint-disable-line new-cap
var users = require('../models/users');
var Fog = require('../models/fog');
var cloudConfig = require('../models/cloud');
var settings = require('../models/settings');
var bCrypt = require('bcrypt-nodejs');
var request = require('request');
var exec = require('child_process').exec;

var isValidPassword = function (user, password) {
  return bCrypt.compareSync(user.password, password);
};

var verifyGatewayOnCloud = function (cloud, gateway, done) {
  request({
    url: 'http://' + cloud.servername + ':' + cloud.port + '/devices/' + gateway.uuid,
    method: 'GET',
    headers: {
      meshblu_auth_uuid: gateway.uuid,
      meshblu_auth_token: gateway.token
    }
  }, function (err, response, body) {
    var data = {};
    var result;
    if (body) {
      result = JSON.parse(body);
    }
    if (err) {
      console.log('Error retrieving gateway from cloud: ' + err);
      err.status = 500;
      done(err, null);
    } else if (!result.devices || result.devices.length === 0) {
      err = {};
      console.log('Gateway not found');
      err.status = 500;
      done(err, null);
    } else {
      data = result.devices[0];
      done(null, data);
    }
  });
};

var verifyUserOnCloud = function (cloud, user, done) {
  request({
    url: 'http://' + cloud.servername + ':' + cloud.port + '/devices/' + user.uuid,
    method: 'GET',
    headers: {
      meshblu_auth_uuid: user.uuid,
      meshblu_auth_token: user.token
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
    } else if (!result.devices || result.devices.length === 0) {
      err = {};
      console.log('User not found');
      err.status = 500;
      done(err, null);
    } else {
      data = result.devices[0];
      done(null, data);
    }
  });
};

var post = function post(req, res) {
  cloudConfig.getCloudSettings(function onCloudSettingsSet(err1, cloud) {
    var user = {};
    var gateway = {};
    if (err1) {
      res.sendStatus(400);
    } else if (!cloud) {
      res.sendStatus(400);
    } else {
      user = {
        uuid: req.body.uuid,
        token: req.body.token,
        email: req.body.email,
        password: req.body.password
      };
      verifyUserOnCloud(cloud, user, function (err2, result) {
        if (err2) {
          res.sendStatus(500);
        } else if (result.uuid === user.uuid && result.user.email === user.email &&
          isValidPassword(user, result.user.password)) {
          user.password = result.user.password;
          users.setUser(user, function (err3) {
            if (err3) {
              res.sendStatus(500);
            } else {
              settings.setUserCredentials(user, function (err4) {
                if (err4) {
                  res.sendStatus(500);
                } else {
                  gateway = {
                    uuid: req.body.gwuuid,
                    token: req.body.gwtoken
                  };
                  verifyGatewayOnCloud(cloud, gateway, function (err5, gwResult) {
                    if (err5) {
                      res.sendStatus(500);
                    } else if (gwResult.owner !== user.uuid) {
                      res.sendStatus(409);
                    } else {
                      Fog.setFogSettings(gateway, function (err6) {
                        if (err6) {
                          res.sendStatus(500);
                        } else {
                          exec('/etc/init.d/S60knot-fog-daemon reload', function (error) {
                            if (error) {
                              console.log('Error restarting KNoT Fog: ' + error);
                            }
                          });
                          res.end();
                        }
                      });
                    }
                  });
                }
              });
            }
          });
        } else {
          res.sendStatus(409);
        }
      });
    }
  });
};

router.post('/', post);

module.exports = {
  router: router
};
