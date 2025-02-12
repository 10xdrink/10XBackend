// services/googleOAuthService.js
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User');
const logger = require('../utils/logger');

const setupGoogleStrategy = () => {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails[0].value;
          let user = await User.findOne({ email });

          if (user) {
            return done(null, user);
          }

          user = new User({
            name: profile.displayName,
            email,
            password: 'google_oauth', // Or handle differently
            role: 'user',
          });

          await user.save();
          done(null, user);
        } catch (error) {
          logger.error('Google OAuth Error:', error);
          done(error, false);
        }
      }
    )
  );

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id).select('-password');
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  });
};

module.exports = setupGoogleStrategy;
