const Settings = require('@overleaf/settings')
const { User } = require('../../models/User')
const UserGetter = require('../User/UserGetter')
const { db, ObjectId } = require('../../infrastructure/mongodb')
const bcrypt = require('bcrypt')
const EmailHelper = require('../Helpers/EmailHelper')
const {
	InvalidEmailError,
	InvalidPasswordError,
	ParallelLoginError,
	PasswordMustBeDifferentError,
} = require('./AuthenticationErrors')
const util = require('util')
const HaveIBeenPwned = require('./HaveIBeenPwned')

const BCRYPT_ROUNDS = Settings.security.bcryptRounds || 12
const BCRYPT_MINOR_VERSION = Settings.security.bcryptMinorVersion || 'a'

const _checkWriteResult = function (result, callback) {
	// for MongoDB
	if (result && result.modifiedCount === 1) {
		callback(null, true)
	} else {
		callback(null, false)
	}
}

const AuthenticationManager = {
	_checkUserPassword(query, password, callback) {
		// Using Mongoose for legacy reasons here. The returned User instance
		// gets serialized into the session and there may be subtle differences
		// between the user returned by Mongoose vs mongodb (such as default values)
		User.findOne(query, (error, user) => {
			if (error) {
				return callback(error)
			}
			if (!user || !user.hashedPassword) {
				return callback(null, null, null)
			}
			bcrypt.compare(password, user.hashedPassword, function (error, match) {
				if (error) {
					return callback(error)
				}
				return callback(null, user, match)
			})
		})
	},


	createUserIfNotExist(oauth_user, callback) {
		// if `oauth_user` has email info
		const oauth_email_exist = process.env.SHARELATEX_OAUTH_COMMON_USER_PROFILE_CONTAIN_EMAIL || 'false';
		let oauth_new_user_email  = "";

		if(oauth_email_exist == 'false'){
			oauth_new_user_email = oauth_user[process.env.SHARELATEX_OAUTH_COMMON_USER_EMAIL_NAME_IDENTIFIER] 
			+ "@" + process.env.SHARELATEX_OAUTH_COMMON_USER_EMAIL_DOMAIN
		}
		else{
			oauth_new_user_email = oauth_user[process.env.SHARELATEX_OAUTH_COMMON_USER_EMAIL_NAME_IDENTIFIER];
		}

		const query = {
			email: oauth_new_user_email
		};
		let parsedEmail = EmailHelper.parseEmail(query.email)
		UserGetter.getUserByAnyEmail(parsedEmail, (error, user) => {
			if ((!user || !user.hashedPassword)) {
				// create random pass for local userdb,for safety
				let pwdSpace = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz0123456789!@#$%^&*()";
				let pwdSpaceLen = pwdSpace.length;
				let result = "";
				for (i = 0; i < 32; i++) {
					result += pwdSpace.charAt(Math.floor(Math.random() * pwdSpaceLen));
				}

				// get passwd
				let pass = result;
				const userRegHand = require('../User/UserRegistrationHandler.js')
				userRegHand.registerNewUser({
					email: query.email,
					first_name: oauth_user.name,
					last_name: "",
					password: pass
				},
					function (error, user) {
						if (error) {
							return callback(error, null);
						}
						user.admin = false
						user.emails[0].confirmedAt = Date.now()
						user.save()
						console.log("user %s added to local library", query.email)
						
						UserGetter.getUserByAnyEmail(EmailHelper.parseEmail(query.email), (error, user) => {
							if (error) {
								return callback(error, null);
							}
							if (user && user.hashedPassword) {
								return callback(null, user);
							} else {
								return callback("Unknown error", null);
							}
						})
					})
			} else {
				return callback(null, user);
			}
		});
	},



	authenticate(query, password, callback) {
		AuthenticationManager._checkUserPassword(
			query,
			password,
			(error, user, match) => {
				if (error) {
					return callback(error)
				}
				if (!user) {
					return callback(null, null)
				}
				const update = { $inc: { loginEpoch: 1 } }
				if (!match) {
					update.$set = { lastFailedLogin: new Date() }
				}
				User.updateOne(
					{ _id: user._id, loginEpoch: user.loginEpoch },
					update,
					{},
					(err, result) => {
						if (err) {
							return callback(err)
						}
						if (result.nModified !== 1) {
							return callback(new ParallelLoginError())
						}
						if (!match) {
							return callback(null, null)
						}
						AuthenticationManager.checkRounds(
							user,
							user.hashedPassword,
							password,
							function (err) {
								if (err) {
									return callback(err)
								}
								callback(null, user)
								HaveIBeenPwned.checkPasswordForReuseInBackground(password)
							}
						)
					}
				)
			}
		)
	},

	validateEmail(email) {
		const parsed = EmailHelper.parseEmail(email)
		if (!parsed) {
			return new InvalidEmailError({ message: 'email not valid' })
		}
		return null
	},

	// validates a password based on a similar set of rules to `complexPassword.js` on the frontend
	// note that `passfield.js` enforces more rules than this, but these are the most commonly set.
	// returns null on success, or an error object.
	validatePassword(password, email) {
		if (password == null) {
			return new InvalidPasswordError({
				message: 'password not set',
				info: { code: 'not_set' },
			})
		}

		let allowAnyChars, min, max
		if (Settings.passwordStrengthOptions) {
			allowAnyChars = Settings.passwordStrengthOptions.allowAnyChars === true
			if (Settings.passwordStrengthOptions.length) {
				min = Settings.passwordStrengthOptions.length.min
				max = Settings.passwordStrengthOptions.length.max
			}
		}
		allowAnyChars = !!allowAnyChars
		min = min || 6
		max = max || 72

		// we don't support passwords > 72 characters in length, because bcrypt truncates them
		if (max > 72) {
			max = 72
		}

		if (password.length < min) {
			return new InvalidPasswordError({
				message: 'password is too short',
				info: { code: 'too_short' },
			})
		}
		if (password.length > max) {
			return new InvalidPasswordError({
				message: 'password is too long',
				info: { code: 'too_long' },
			})
		}
		if (
			!allowAnyChars &&
			!AuthenticationManager._passwordCharactersAreValid(password)
		) {
			return new InvalidPasswordError({
				message: 'password contains an invalid character',
				info: { code: 'invalid_character' },
			})
		}
		if (typeof email === 'string' && email !== '') {
			const startOfEmail = email.split('@')[0]
			if (
				password.indexOf(email) !== -1 ||
				password.indexOf(startOfEmail) !== -1
			) {
				return new InvalidPasswordError({
					message: 'password contains part of email address',
					info: { code: 'contains_email' },
				})
			}
		}
		return null
	},

	setUserPassword(user, password, callback) {
		AuthenticationManager.setUserPasswordInV2(user, password, callback)
	},

	checkRounds(user, hashedPassword, password, callback) {
		// Temporarily disable this function, TODO: re-enable this
		if (Settings.security.disableBcryptRoundsUpgrades) {
			return callback()
		}
		// check current number of rounds and rehash if necessary
		const currentRounds = bcrypt.getRounds(hashedPassword)
		if (currentRounds < BCRYPT_ROUNDS) {
			AuthenticationManager.setUserPassword(user, password, callback)
		} else {
			callback()
		}
	},

	hashPassword(password, callback) {
		bcrypt.genSalt(BCRYPT_ROUNDS, BCRYPT_MINOR_VERSION, function (error, salt) {
			if (error) {
				return callback(error)
			}
			bcrypt.hash(password, salt, callback)
		})
	},

	setUserPasswordInV2(user, password, callback) {
		if (!user || !user.email || !user._id) {
			return callback(new Error('invalid user object'))
		}
		const validationError = this.validatePassword(password, user.email)
		if (validationError) {
			return callback(validationError)
		}
		// check if we can log in with this password. In which case we should reject it,
		// because it is the same as the existing password.
		AuthenticationManager._checkUserPassword(
			{ _id: user._id },
			password,
			(err, _user, match) => {
				if (err) {
					return callback(err)
				}
				if (match) {
					return callback(new PasswordMustBeDifferentError())
				}
				this.hashPassword(password, function (error, hash) {
					if (error) {
						return callback(error)
					}
					db.users.updateOne(
						{
							_id: ObjectId(user._id.toString()),
						},
						{
							$set: {
								hashedPassword: hash,
							},
							$unset: {
								password: true,
							},
						},
						function (updateError, result) {
							if (updateError) {
								return callback(updateError)
							}
							_checkWriteResult(result, callback)
							HaveIBeenPwned.checkPasswordForReuseInBackground(password)
						}
					)
				})
			}
		)
	},

	_passwordCharactersAreValid(password) {
		let digits, letters, lettersUp, symbols
		if (
			Settings.passwordStrengthOptions &&
			Settings.passwordStrengthOptions.chars
		) {
			digits = Settings.passwordStrengthOptions.chars.digits
			letters = Settings.passwordStrengthOptions.chars.letters
			lettersUp = Settings.passwordStrengthOptions.chars.letters_up
			symbols = Settings.passwordStrengthOptions.chars.symbols
		}
		digits = digits || '1234567890'
		letters = letters || 'abcdefghijklmnopqrstuvwxyz'
		lettersUp = lettersUp || 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
		symbols = symbols || '@#$%^&*()-_=+[]{};:<>/?!£€.,'

		for (let charIndex = 0; charIndex <= password.length - 1; charIndex++) {
			if (
				digits.indexOf(password[charIndex]) === -1 &&
				letters.indexOf(password[charIndex]) === -1 &&
				lettersUp.indexOf(password[charIndex]) === -1 &&
				symbols.indexOf(password[charIndex]) === -1
			) {
				return false
			}
		}
		return true
	},
}

AuthenticationManager.promises = {
	authenticate: util.promisify(AuthenticationManager.authenticate),
	hashPassword: util.promisify(AuthenticationManager.hashPassword),
	setUserPassword: util.promisify(AuthenticationManager.setUserPassword),
}

module.exports = AuthenticationManager
