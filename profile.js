/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth2')
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};

  OAuth2Strategy.call(this, options, verify);
  this._profileURL = options.profileURL;
  this._profileTokenHeader = options.profileTokenHeader;
  this._profileTokenFormat = options.profileTokenFormat;
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  if(this._profileURL){
    var headers = {};
    headers[this._profileTokenHeader] = this._profileTokenFormat.format({"accessToken": accessToken});
    this._oauth2._request('GET', this._userProfileURL, headers, "", accessToken, function (err, body, res) {
      var json;
      
      if (err) {
        return done(new InternalOAuthError('Failed to fetch user profile', err));
      }
      
      try {
        json = JSON.parse(body);
      } catch (ex) {
        return done(new Error('Failed to parse user profile'));
      }
      
      var profile = {};
      profile._raw = body;
      profile._json = json;
      
      done(null, profile);
    });
  } else {
      done(null, {});
  }
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;