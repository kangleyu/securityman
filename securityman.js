'use strict';

var jwt = require('jsonwebtoken');

/**
 * Authentication and Authorization module
 * Parameters:
 *  app -- express app
 *  usermodel -- mongoose User model which will be used to operate on mongodb for persisting user info
 *  options -- options for module
 *    --- secret => secret used for generating jwt token
 *    --- expiresIn => expires time for jwt token
 */
module.exports = function(app, usermodel, options) {
  // Do some verification before keeping on
  // -- app must has Router
  // -- usermodel must has username/passwrod etc
  // -- options must has secret and expiresIn

  var router = app.Router;
  var username = usermodel.username || undefined;
  var password = usermodel.password || undefined;
  var secret = options.secret || 'DEFAULT_SECRET_SECURITYMAN';

  // define private methods here



  // define public methods here
  return {
    // sign up for a new user
    sigup: function(usermodel) {

    },

    // sign in with username and password
    signin: function(req, res) {
      usermodel.findOne({
        name: req.body.name
      }, function(err, user) {
        if (err) {
          throw err;
        }

        if (!user) {
          res.json({ success: false, message: 'Authentication failed, user was not found.'});
        } else if (user) {
          // TODO: we should hash the password
          if (user.password != req.body.password) {
            res.json({ success: false, message: 'Authentication failed, invalid password'});
          } else {
            var token = jwt.sign(user, options.secret, {
              expiresIn: options.expiresIn
            });
            res.json({
              success: true,
              message: 'Welcome back ' + user.username,
              token: token
            });
          }
        }
      });
    },

    // sign out for current user
    signout: function(username) {

    },

    // express middleware for authentication & authorization
    verify: function(req, res, next) {
      var token = req.body.token || req.query.token || req.headers['x-access-token'];
      if (token) {
        jwt.verify(token, options.secret, function(err, decoded) {
          if (err) {
            return res.json({ success: false, message: 'Invalid token.'});
          } else {
            req.decoded = decoded;
            next();
          }
        });
      } else {
        return res.status(404).send({
          success: false,
          message: 'Please provide valid token.'
        })
      }
    }
  };
};