require('dotenv').config();

const express = require('express');
const app = express();
const port = process.env.PORT || 8080;

const { auth, requiresAuth } = require("express-openid-connect");

const passport = require('passport');
const Auth0Strategy = require('passport-auth0');
const session = require('express-session');	
const bodyParser = require('body-parser');

const authRouter = require("./auth");
const mongoose = require('mongoose');

// Configure Passport to use Auth0
const strategy = new Auth0Strategy(
  {
    domain: process.env.AUTH0_DOMAIN,
    clientID: process.env.AUTH0_CLIENT_ID,
    clientSecret: process.env.AUTH0_CLIENT_SECRET,
    callbackURL:
	'http://localhost:8080/callback' || 'http://localhost:3000/callback'
  },
  function (accessToken, refreshToken, extraParams, profile, done) { // finds the user that possesses a set of credentials
    return done(null, profile);
  }
);

app.set('views', '');
app.set('view engine', 'pug');
// app.use(express.static(path.join(__dirname, 'public')));

app.use(bodyParser.urlencoded({
	extended: true
}));
app.use(bodyParser.json())  

const sess = {
	secret: process.env.SESS_SECRET, // to sign the session ID cookie
	cookie: {}, // for the session ID cookie
	resave: false, // forces the session to be saved back to the session store, even if the application doesn't modify the session during the request
	saveUninitialized: false // forces a session that is new, but not modified, uninitialized, to be saved to the store
};
if (app.get('env') === 'production') {
	sess.cookie.secure = true; // serve secure cookies, requires https
}
app.use(session(sess));

passport.use(strategy);
app.use(passport.initialize()); // always after app.use(session(sess));
app.use(passport.session()); // always after app.use(session(sess));
passport.serializeUser(function (user, done) {
	done(null, user);
});
passport.deserializeUser(function (user, done) {
	done(null, user);
});

// Creating custom middleware with Express
app.use((req, res, next) => {
	res.locals.isAuthenticated = req.isAuthenticated();
	next();
});  
app.use("/", authRouter);

app.get('/', (req, res, next) => res.render('index'));

const secured = (req, res, next) => {
	if (req.user) return next();
	
	req.session.returnTo = req.originalUrl;
	res.redirect('/login');
};

  
app.get('/user', secured, (req, res, next) => {
	const { _raw, _json, ...userProfile } = req.user; // Javascript object destructuring 
	
	// console.log('userProfile -> ', userProfile);
	
	res.render('user', {
	  title: 'Profile',
	  userProfile: userProfile
	});
});

// MONGODB NOT REQUIRED NOW, MAYBE LATER?
// mongoose.connect(process.env.MONGO_URL, {
// 	useNewUrlParser: true, useUnifiedTopology: true})
// 	.catch(error => console.log(error)); //TODO test error connection
// mongoose.connection.on('error', err => {
// 	console.log(err);
// });
  
  

app.listen(port, () => {console.log('Listening on port ', port);});

