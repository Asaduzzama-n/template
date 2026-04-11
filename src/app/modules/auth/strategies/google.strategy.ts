import passport from 'passport'
import { User } from '../../user/user.model'
import { Strategy as GoogleStrategy } from 'passport-google-oauth20'
import config from '../../../../config'
import { USER_ROLES } from '../../../../enum/user'

passport.use(
  new GoogleStrategy(
    {
      clientID: config.google.client_id!,
      clientSecret: config.google.client_secret!,
      callbackURL: config.google.callback_url,
      passReqToCallback: true,
    },
    async (req, accessToken, refreshToken, profile, done) => {
      // Attach the profile to req.body so the controller can access it
      req.body.profile = profile
      // Default role for new social users
      req.body.role = USER_ROLES.CUSTOMER

      try {
        return done(null, req.body)
      } catch (err) {
        return done(err)
      }
    },
  ),
)

export default passport
