const AuthenticationManager = require('./AuthenticationManager')
const axios = require('axios')
const fs = require('fs')
const jwt = require('jsonwebtoken')
const NodeRSA = require('node-rsa');
const SessionManager = require('./SessionManager')
const OError = require('@overleaf/o-error')
const LoginRateLimiter = require('../Security/LoginRateLimiter')
const UserUpdater = require('../User/UserUpdater')
const Metrics = require('@overleaf/metrics')
const logger = require('@overleaf/logger')
const querystring = require('querystring')
const Settings = require('@overleaf/settings')
const basicAuth = require('basic-auth')
const tsscmp = require('tsscmp')
const UserHandler = require('../User/UserHandler')
const UserSessionsManager = require('../User/UserSessionsManager')
const SessionStoreManager = require('../../infrastructure/SessionStoreManager')
const Analytics = require('../Analytics/AnalyticsManager')
const passport = require('passport')
const NotificationsBuilder = require('../Notifications/NotificationsBuilder')
const UrlHelper = require('../Helpers/UrlHelper')
const AsyncFormHelper = require('../Helpers/AsyncFormHelper')
const _ = require('lodash')
const UserAuditLogHandler = require('../User/UserAuditLogHandler')
const AnalyticsRegistrationSourceHelper = require('../Analytics/AnalyticsRegistrationSourceHelper')
const {
	acceptsJson,
} = require('../../infrastructure/RequestContentTypeDetection')
const { ParallelLoginError } = require('./AuthenticationErrors')
const { hasAdminAccess } = require('../Helpers/AdminAuthorizationHelper')
const Modules = require('../../infrastructure/Modules')

function send401WithChallenge(res) {
	res.setHeader('WWW-Authenticate', 'OverleafLogin')
	res.sendStatus(401)
}

function checkCredentials(userDetailsMap, user, password) {
	const expectedPassword = userDetailsMap.get(user)
	const userExists = userDetailsMap.has(user) && expectedPassword // user exists with a non-null password
	const isValid = userExists && tsscmp(expectedPassword, password)
	if (!isValid) {
		logger.err({ user }, 'invalid login details')
	}
	Metrics.inc('security.http-auth.check-credentials', 1, {
		path: userExists ? 'known-user' : 'unknown-user',
		status: isValid ? 'pass' : 'fail',
	})
	return isValid
}

const AuthenticationController = {
	serializeUser(user, callback) {
		if (!user._id || !user.email) {
			const err = new Error('serializeUser called with non-user object')
			logger.warn({ user }, err.message)
			return callback(err)
		}
		const lightUser = {
			_id: user._id,
			first_name: user.first_name,
			last_name: user.last_name,
			isAdmin: user.isAdmin,
			staffAccess: user.staffAccess,
			email: user.email,
			referal_id: user.referal_id,
			session_created: new Date().toISOString(),
			ip_address: user._login_req_ip,
			must_reconfirm: user.must_reconfirm,
			v1_id: user.overleaf != null ? user.overleaf.id : undefined,
			analyticsId: user.analyticsId || user._id,
		}
		callback(null, lightUser)
	},

	deserializeUser(user, cb) {
		cb(null, user)
	},

	passportLogin(req, res, next) {
		// This function is middleware which wraps the passport.authenticate middleware,
		// so we can send back our custom `{message: {text: "", type: ""}}` responses on failure,
		// and send a `{redir: ""}` response on success
		passport.authenticate('local', function (err, user, info) {
			if (err) {
				return next(err)
			}
			if (user) {
				// `user` is either a user object or false
				AuthenticationController.setAuditInfo(req, { method: 'Password login' })
				return AuthenticationController.finishLogin(user, req, res, next)
			} else {
				if (info.redir != null) {
					return res.json({ redir: info.redir })
				} else {
					res.status(info.status || 200)
					delete info.status
					const body = { message: info }
					const { errorReason } = info
					if (errorReason) {
						body.errorReason = errorReason
						delete info.errorReason
					}
					return res.json(body)
				}
			}
		})(req, res, next)
	},

	finishLogin(user, req, res, next) {
		if (user === false) {
			return res.redirect('/login')
		} // OAuth2 'state' mismatch

		if (Settings.adminOnlyLogin && !hasAdminAccess(user)) {
			return res.status(403).json({
				message: { type: 'error', text: 'Admin only panel' },
			})
		}

		const auditInfo = AuthenticationController.getAuditInfo(req)

		const anonymousAnalyticsId = req.session.analyticsId
		const isNewUser = req.session.justRegistered || false

		Modules.hooks.fire(
			'preFinishLogin',
			req,
			res,
			user,
			function (error, results) {
				if (error) {
					return next(error)
				}
				if (results.some(result => result && result.doNotFinish)) {
					return
				}

				if (user.must_reconfirm) {
					return AuthenticationController._redirectToReconfirmPage(
						req,
						res,
						user
					)
				}

				const redir =
					AuthenticationController._getRedirectFromSession(req) || '/project'
				_loginAsyncHandlers(req, user, anonymousAnalyticsId, isNewUser)
				const userId = user._id
				UserAuditLogHandler.addEntry(
					userId,
					'login',
					userId,
					req.ip,
					auditInfo,
					err => {
						if (err) {
							return next(err)
						}
						_afterLoginSessionSetup(req, user, function (err) {
							if (err) {
								return next(err)
							}
							AuthenticationController._clearRedirectFromSession(req)
							AnalyticsRegistrationSourceHelper.clearSource(req.session)
							AnalyticsRegistrationSourceHelper.clearInbound(req.session)
							AsyncFormHelper.redirect(req, res, redir)
						})
					}
				)
			}
		)
	},

	doPassportLogin(req, username, password, done) {
		const email = username.toLowerCase()
		Modules.hooks.fire(
			'preDoPassportLogin',
			req,
			email,
			function (err, infoList) {
				if (err) {
					return done(err)
				}
				const info = infoList.find(i => i != null)
				if (info != null) {
					return done(null, false, info)
				}
				LoginRateLimiter.processLoginRequest(email, function (err, isAllowed) {
					if (err) {
						return done(err)
					}
					if (!isAllowed) {
						logger.debug({ email }, 'too many login requests')
						return done(null, null, {
							text: req.i18n.translate('to_many_login_requests_2_mins'),
							type: 'error',
							status: 429,
						})
					}
					AuthenticationManager.authenticate(
						{ email },
						password,
						function (error, user) {
							if (error != null) {
								if (error instanceof ParallelLoginError) {
									return done(null, false, { status: 429 })
								}
								return done(error)
							}
							if (
								user &&
								AuthenticationController.captchaRequiredForLogin(req, user)
							) {
								done(null, false, {
									text: req.i18n.translate('cannot_verify_user_not_robot'),
									type: 'error',
									errorReason: 'cannot_verify_user_not_robot',
									status: 400,
								})
							} else if (user) {
								// async actions
								done(null, user)
							} else {
								AuthenticationController._recordFailedLogin()
								logger.debug({ email }, 'failed log in')
								done(null, false, {
									text: req.i18n.translate('email_or_password_wrong_try_again'),
									type: 'error',
									status: 401,
								})
							}
						}
					)
				})
			}
		)
	},

	captchaRequiredForLogin(req, user) {
		switch (AuthenticationController.getAuditInfo(req).captcha) {
			case 'disabled':
				return false
			case 'solved':
				return false
			case 'skipped': {
				let required = false
				if (user.lastFailedLogin) {
					const requireCaptchaUntil =
						user.lastFailedLogin.getTime() +
						Settings.elevateAccountSecurityAfterFailedLogin
					required = requireCaptchaUntil >= Date.now()
				}
				Metrics.inc('force_captcha_on_login', 1, {
					status: required ? 'yes' : 'no',
				})
				return required
			}
			default:
				throw new Error('captcha middleware missing in handler chain')
		}
	},

	ipMatchCheck(req, user) {
		if (req.ip !== user.lastLoginIp) {
			NotificationsBuilder.ipMatcherAffiliation(user._id).create(
				req.ip,
				() => { }
			)
		}
		return UserUpdater.updateUser(
			user._id.toString(),
			{
				$set: { lastLoginIp: req.ip },
			},
			() => { }
		)
	},

	requireLogin() {
		const doRequest = function (req, res, next) {
			if (next == null) {
				next = function () { }
			}
			if (!SessionManager.isUserLoggedIn(req.session)) {
				if (acceptsJson(req)) return send401WithChallenge(res)
				return AuthenticationController._redirectToLoginOrRegisterPage(req, res)
			} else {
				req.user = SessionManager.getSessionUser(req.session)
				return next()
			}
		}

		return doRequest
	},

	// ####################################################################################
	// 	 					 _         _____ _____  ____  
	// 	   /\               | |       / ____/ ____|/ __ \ 
	//    /  \   _ __  _ __ | | ___  | (___| (___ | |  | |
	//   / /\ \ | '_ \| '_ \| |/ _ \  \___ \\___ \| |  | |
	//  / ____ \| |_) | |_) | |  __/  ____) |___) | |__| |
	// /_/    \_\ .__/| .__/|_|\___| |_____/_____/ \____/ 
	// 		 	| |   | |                                 
	// 		 	|_|   |_|                                        
														  
	// OAuth For Apple Only!

	oauthAppleRedirect(req, res, next){
		const oauth_apple_allowed = process.env.SHARELATEX_OAUTH_APPLE_ENABLED || 'false';
		if(oauth_apple_allowed == 'true'){

			res.redirect(`${process.env.SHARELATEX_OAUTH_APPLE_AUTH_URL}?` +
			querystring.stringify({
				client_id: process.env.SHARELATEX_OAUTH_APPLE_CLIENT_ID,
				response_type: "code id_token",
				response_mode: "form_post",
				scope: process.env.SHARELATEX_OAUTH_APPLE_SCOPE,
				redirect_uri: (process.env.SHARELATEX_OAUTH_APPLE_REDIRECT_URL),
			}));
		}
	},


	oauthAppleGetClientSecret(){
		console.log('oauthAppleGetClientSecret start!!!!!!!!!!!!!!!!!!!');
		const privateKey = process.env.SHARELATEX_OAUTH_APPLE_AUTH_SERVICE_SECRET_KEY;
		// const privateKey = fs.readFileSync('/overleaf/services/web/app/src/Features/Authentication/AuthKey_R37J7XV25W.p8', { encoding: "utf-8" });
		console.log(privateKey);
		const headers = {
			alg: 'ES256',
			kid: process.env.SHARELATEX_OAUTH_APPLE_AUTH_SERVICE_SECRET_KEY_ID,
		}
		const timeNow = Math.floor(Date.now() / 1000);
		const claims = {
			iss: process.env.SHARELATEX_OAUTH_APPLE_DEVELOPER_TEAM_ID,
			aud: 'https://appleid.apple.com',
			sub: process.env.SHARELATEX_OAUTH_APPLE_CLIENT_ID,
			iat: timeNow,
			exp: timeNow + 1800,
		};
		token = jwt.sign(claims, privateKey, {algorithm: 'ES256',header: headers});
		console.log('oauthAppleGetClientSecret end!!!!!!!!!!!!!!!!!!!');
		console.log(token);
		return token;
	},

	async oauthAppleGetPublicKey(kid){
		let res = await axios.request({
			method: "GET",
			url: process.env.SHARELATEX_OAUTH_APPLE_PUBLIC_KEY_URL,
		});
		const keys = res.data.keys;
		const key = keys.find(k => k.kid === kid);
		const pubKey = new NodeRSA();

		pubKey.importKey({ n: Buffer.from(key.n, 'base64'), e: Buffer.from(key.e, 'base64') }, 'components-public');
		return pubKey.exportKey(['public']);
	},

	async oauthAppleVerifyIDToken (idToken, clientID){
		if (!idToken) {
			let error = new Error("OBJECT_NOT_FOUND", 'id token is invalid for this user.')
			console.error('ERROR_ACCOUNT_CREATION_FAILED');
			throw error;
		}
		let jwtClaims = {};
		try {
			const decodedToken = jwt.decode(idToken, { complete: true });
			const applePublicKey = await AuthenticationController.oauthAppleGetPublicKey(decodedToken.header.kid);
			jwtClaims = jwt.verify(idToken, applePublicKey, { algorithms: 'RS256' });
		}catch (err) {
			console.log('get apple public key', err);
			throw new Error("publickey", 'apple public key is invalid for this user.');;
		}

		console.log('[jwtClaims is ]:', jwtClaims);
		return jwtClaims;
	},

	oauthAppleCallback(req, res, next){
		// console.log("[oauthApple Callback req is]:" + req);
		const oauth_allowed = process.env.SHARELATEX_OAUTH_APPLE_ENABLED || 'false';
		if(oauth_allowed == 'false'){
			return;
		}

		const params = new URLSearchParams()
		params.append('grant_type', "authorization_code")
		params.append('client_id', process.env.SHARELATEX_OAUTH_APPLE_CLIENT_ID)
		params.append('client_secret', AuthenticationController.oauthAppleGetClientSecret())
		params.append("code", req.body.code)
		params.append('redirect_uri', (process.env.SHARELATEX_OAUTH_APPLE_REDIRECT_URL))

		console.log("[oauthApple Callback params will POST is]:" + params.toString());

		axios.post(process.env.SHARELATEX_OAUTH_APPLE_TOKEN_URL, params, {
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
			}
		}).then(response => {
			console.log("[oauthApple Callback POST responese]:" +response);
			AuthenticationController.oauthAppleVerifyIDToken(response.data.id_token, process.env.SHARELATEX_OAUTH_APPLE_CLIENT_ID).then(
				(jwtClaims) => {
					console.log(jwtClaims);
					return res.json({
						message: 'success',
						data: response.data,
						verifyData: jwtClaims
					})
			});
			
		}).catch(error => {
			return res.status(500).json({
				message: '错误',
				error: error.response.data
			})
		})


	},




	// ####################################################################################





	// ####################################################################################
	// Common OAuth For Github、Google And So On.
	// URL: /auth/oauth/common/redirect
	oauthCommonRedirect(req, res, next) {
		const oauth_allowed = process.env.SHARELATEX_OAUTH_COMMON_ENABLED || 'false';
		if(oauth_allowed == 'true'){
			res.redirect(`${process.env.SHARELATEX_OAUTH_COMMON_AUTH_URL}?` +
			querystring.stringify({
				client_id: process.env.SHARELATEX_OAUTH_COMMON_CLIENT_ID,
				response_type: "code",
				scope: process.env.SHARELATEX_OAUTH_COMMON_SCOPE,
				redirect_uri: (process.env.SHARELATEX_OAUTH_COMMON_REDIRECT_URL),
			}));
		}
	},

	// URL: /auth/oauth/common/callback
	oauthCommonCallback(req, res, next) {
		const oauth_allowed = process.env.SHARELATEX_OAUTH_COMMON_ENABLED || 'false';
		if(oauth_allowed == 'false'){
			return;
		}

		const params = new URLSearchParams()
		params.append('grant_type', "authorization_code")
		params.append('client_id', process.env.SHARELATEX_OAUTH_COMMON_CLIENT_ID)
		params.append('client_secret', process.env.SHARELATEX_OAUTH_COMMON_CLIENT_SECRET)
		params.append("code", req.query.code)
		params.append('redirect_uri', (process.env.SHARELATEX_OAUTH_COMMON_REDIRECT_URL))


		axios.post(process.env.SHARELATEX_OAUTH_COMMON_ACCESS_TOKEN_URL, params, {
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				"Accept": "application/json"
			}
		}).then(access_res => {
			authorization_bearer = "Bearer " + access_res.data.access_token

			let axios_get_config = {
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					"Authorization": authorization_bearer,
				},
				params: access_res.data
			}

			axios.get(process.env.SHARELATEX_OAUTH_COMMON_USER_PROFILE_URL, axios_get_config).then(info_res => {
				if (info_res.data.err) {
					res.json({ message: info_res.data.err });
				} else {
					AuthenticationManager.createUserIfNotExist(info_res.data, (error, user) => {
						if (error) {
							res.json({ message: error });
						} else {
							AuthenticationController.finishLogin(user, req, res, next);
						}
					});
				}
			});
		});
	},

	// ####################################################################################

	requireOauth() {
		// require this here because module may not be included in some versions
		const Oauth2Server = require('../../../../modules/oauth2-server/app/src/Oauth2Server')
		return function (req, res, next) {
			if (next == null) {
				next = function () { }
			}
			const request = new Oauth2Server.Request(req)
			const response = new Oauth2Server.Response(res)
			return Oauth2Server.server.authenticate(
				request,
				response,
				{},
				function (err, token) {
					if (err) {
						// use a 401 status code for malformed header for git-bridge
						if (
							err.code === 400 &&
							err.message === 'Invalid request: malformed authorization header'
						) {
							err.code = 401
						}
						// send all other errors
						return res
							.status(err.code)
							.json({ error: err.name, error_description: err.message })
					}
					req.oauth = { access_token: token.accessToken }
					req.oauth_token = token
					req.oauth_user = token.user
					return next()
				}
			)
		}
	},

	validateUserSession: function () {
		// Middleware to check that the user's session is still good on key actions,
		// such as opening a a project. Could be used to check that session has not
		// exceeded a maximum lifetime (req.session.session_created), or for session
		// hijacking checks (e.g. change of ip address, req.session.ip_address). For
		// now, just check that the session has been loaded from the session store
		// correctly.
		return function (req, res, next) {
			// check that the session store is returning valid results
			if (req.session && !SessionStoreManager.hasValidationToken(req)) {
				// force user to update session
				req.session.regenerate(() => {
					// need to destroy the existing session and generate a new one
					// otherwise they will already be logged in when they are redirected
					// to the login page
					if (acceptsJson(req)) return send401WithChallenge(res)
					AuthenticationController._redirectToLoginOrRegisterPage(req, res)
				})
			} else {
				next()
			}
		}
	},

	_globalLoginWhitelist: [],
	addEndpointToLoginWhitelist(endpoint) {
		return AuthenticationController._globalLoginWhitelist.push(endpoint)
	},

	requireGlobalLogin(req, res, next) {
		if (
			AuthenticationController._globalLoginWhitelist.includes(
				req._parsedUrl.pathname
			)
		) {
			return next()
		}

		if (req.headers.authorization != null) {
			AuthenticationController.requirePrivateApiAuth()(req, res, next)
		} else if (SessionManager.isUserLoggedIn(req.session)) {
			next()
		} else {
			logger.debug(
				{ url: req.url },
				'user trying to access endpoint not in global whitelist'
			)
			if (acceptsJson(req)) return send401WithChallenge(res)
			AuthenticationController.setRedirectInSession(req)
			res.redirect('/login')
		}
	},

	validateAdmin(req, res, next) {
		const adminDomains = Settings.adminDomains
		if (
			!adminDomains ||
			!(Array.isArray(adminDomains) && adminDomains.length)
		) {
			return next()
		}
		const user = SessionManager.getSessionUser(req.session)
		if (!hasAdminAccess(user)) {
			return next()
		}
		const email = user.email
		if (email == null) {
			return next(
				new OError('[ValidateAdmin] Admin user without email address', {
					userId: user._id,
				})
			)
		}
		if (!adminDomains.find(domain => email.endsWith(`@${domain}`))) {
			return next(
				new OError('[ValidateAdmin] Admin user with invalid email domain', {
					email,
					userId: user._id,
				})
			)
		}
		return next()
	},

	checkCredentials,

	requireBasicAuth: function (userDetails) {
		const userDetailsMap = new Map(Object.entries(userDetails))
		return function (req, res, next) {
			const credentials = basicAuth(req)
			if (
				!credentials ||
				!checkCredentials(userDetailsMap, credentials.name, credentials.pass)
			) {
				send401WithChallenge(res)
				Metrics.inc('security.http-auth', 1, { status: 'reject' })
			} else {
				Metrics.inc('security.http-auth', 1, { status: 'accept' })
				next()
			}
		}
	},

	requirePrivateApiAuth() {
		return AuthenticationController.requireBasicAuth(Settings.httpAuthUsers)
	},

	setAuditInfo(req, info) {
		if (!req.__authAuditInfo) {
			req.__authAuditInfo = {}
		}
		Object.assign(req.__authAuditInfo, info)
	},

	getAuditInfo(req) {
		return req.__authAuditInfo || {}
	},

	setRedirectInSession(req, value) {
		if (value == null) {
			value =
				Object.keys(req.query).length > 0
					? `${req.path}?${querystring.stringify(req.query)}`
					: `${req.path}`
		}
		if (
			req.session != null &&
			!/^\/(socket.io|js|stylesheets|img)\/.*$/.test(value) &&
			!/^.*\.(png|jpeg|svg)$/.test(value)
		) {
			const safePath = UrlHelper.getSafeRedirectPath(value)
			return (req.session.postLoginRedirect = safePath)
		}
	},

	_redirectToLoginOrRegisterPage(req, res) {
		if (
			req.query.zipUrl != null ||
			req.query.project_name != null ||
			req.path === '/user/subscription/new'
		) {
			AuthenticationController._redirectToRegisterPage(req, res)
		} else {
			AuthenticationController._redirectToLoginPage(req, res)
		}
	},

	_redirectToLoginPage(req, res) {
		logger.debug(
			{ url: req.url },
			'user not logged in so redirecting to login page'
		)
		AuthenticationController.setRedirectInSession(req)
		const url = `/login?${querystring.stringify(req.query)}`
		res.redirect(url)
		Metrics.inc('security.login-redirect')
	},

	_redirectToReconfirmPage(req, res, user) {
		logger.debug(
			{ url: req.url },
			'user needs to reconfirm so redirecting to reconfirm page'
		)
		req.session.reconfirm_email = user != null ? user.email : undefined
		const redir = '/user/reconfirm'
		AsyncFormHelper.redirect(req, res, redir)
	},

	_redirectToRegisterPage(req, res) {
		logger.debug(
			{ url: req.url },
			'user not logged in so redirecting to register page'
		)
		AuthenticationController.setRedirectInSession(req)
		const url = `/register?${querystring.stringify(req.query)}`
		res.redirect(url)
		Metrics.inc('security.login-redirect')
	},

	_recordSuccessfulLogin(userId, callback) {
		if (callback == null) {
			callback = function () { }
		}
		UserUpdater.updateUser(
			userId.toString(),
			{
				$set: { lastLoggedIn: new Date() },
				$inc: { loginCount: 1 },
			},
			function (error) {
				if (error != null) {
					callback(error)
				}
				Metrics.inc('user.login.success')
				callback()
			}
		)
	},

	_recordFailedLogin(callback) {
		Metrics.inc('user.login.failed')
		if (callback) callback()
	},

	_getRedirectFromSession(req) {
		let safePath
		const value = _.get(req, ['session', 'postLoginRedirect'])
		if (value) {
			safePath = UrlHelper.getSafeRedirectPath(value)
		}
		return safePath || null
	},

	_clearRedirectFromSession(req) {
		if (req.session != null) {
			delete req.session.postLoginRedirect
		}
	},
}

function _afterLoginSessionSetup(req, user, callback) {
	if (callback == null) {
		callback = function () { }
	}
	req.login(user, function (err) {
		if (err) {
			OError.tag(err, 'error from req.login', {
				user_id: user._id,
			})
			return callback(err)
		}
		// Regenerate the session to get a new sessionID (cookie value) to
		// protect against session fixation attacks
		const oldSession = req.session
		req.session.destroy(function (err) {
			if (err) {
				OError.tag(err, 'error when trying to destroy old session', {
					user_id: user._id,
				})
				return callback(err)
			}
			req.sessionStore.generate(req)
			// Note: the validation token is not writable, so it does not get
			// transferred to the new session below.
			for (const key in oldSession) {
				const value = oldSession[key]
				if (key !== '__tmp' && key !== 'csrfSecret') {
					req.session[key] = value
				}
			}
			req.session.save(function (err) {
				if (err) {
					OError.tag(err, 'error saving regenerated session after login', {
						user_id: user._id,
					})
					return callback(err)
				}
				UserSessionsManager.trackSession(user, req.sessionID, function () { })
				if (!req.deviceHistory) {
					// Captcha disabled or SSO-based login.
					return callback()
				}
				req.deviceHistory.add(user.email)
				req.deviceHistory
					.serialize(req.res)
					.catch(err => {
						logger.err({ err }, 'cannot serialize deviceHistory')
					})
					.finally(() => callback())
			})
		})
	})
}

function _loginAsyncHandlers(req, user, anonymousAnalyticsId, isNewUser) {
	UserHandler.setupLoginData(user, err => {
		if (err != null) {
			logger.warn({ err }, 'error setting up login data')
		}
	})
	LoginRateLimiter.recordSuccessfulLogin(user.email, () => { })
	AuthenticationController._recordSuccessfulLogin(user._id, () => { })
	AuthenticationController.ipMatchCheck(req, user)
	Analytics.recordEventForUser(user._id, 'user-logged-in', {
		source: req.session.saml
			? 'saml'
			: req.user_info?.auth_provider || 'email-password',
	})
	Analytics.identifyUser(user._id, anonymousAnalyticsId, isNewUser)

	logger.debug(
		{ email: user.email, user_id: user._id.toString() },
		'successful log in'
	)

	req.session.justLoggedIn = true
	// capture the request ip for use when creating the session
	return (user._login_req_ip = req.ip)
}

module.exports = AuthenticationController
