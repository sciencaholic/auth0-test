require('dotenv').config();

const express = require('express');
const router = express.Router();
const passport = require('passport');

const url = require('url');
const util = require('util');
const querystring = require('querystring');
const request = require('request');


router.get('/login', passport.authenticate('auth0', { scope:'openid email profile'}), function (req, res) {
	res.redirect('/');
});

router.get('/callback', (req, res, next) => {
	passport.authenticate('auth0', (err, user, info) => {
		if (err) return next(err);
		if (!user) return res.redirect('/login');
		
		req.logIn(user, (err) => { // establishes a login session
			if (err) return next(err);
			
			// redirect to the page user was visiting before the authentication request took place
			const returnTo = req.session.returnTo;
			delete req.session.returnTo;
			res.redirect(returnTo || '/');
		});
	})(req, res, next);
});

router.get('/logout', (req, res) => {
	req.logOut(); // removes the req.user property and clears the existing login session
  
	let returnTo = req.protocol + '://' + req.hostname;
	const port = req.connection.localPort;
  
	if (port !== undefined && port !== 80 && port !== 443) {
	  returnTo =
		process.env.NODE_ENV === 'production'
		  ? `${returnTo}/`
		  : `${returnTo}:${port}/`;
	}
  
	const logoutURL = new URL(`https://${process.env.AUTH0_DOMAIN}/logout`);
	// const logoutURL = new URL(util.format('https://%s/logout', process.env.AUTH0_DOMAIN));

	const searchString = querystring.stringify({ // create a URL query string from an object that contains the Auth0 client ID and the returnTo URL
	  client_id: process.env.AUTH0_CLIENT_ID,
	  returnTo: returnTo
	});
	logoutURL.search = searchString; // get and set the serialized query portions of logoutURL

	console.log('Logged out!');  
	res.redirect(logoutURL);
});

router.post('/change-password', (req, res, next) => {
	const options = {
		method: 'POST',
		url: `https://${process.env.AUTH0_DOMAIN}/dbconnections/change_password`,
		headers: {'content-type': 'application/json'},
		body: {
			client_id: process.env.AUTH0_CLIENT_ID,
			email: req.user.emails[0].value,
			connection: 'Username-Password-Authentication'
		},
		json: true
	};

	request(options, function (error, response, body) {
		if (error) throw new Error(error);

		console.log(body);
		return res.json({success: true});
	});
})

// ------------------------------------------------------------------------------------------------------------------------------

router.post('/add-to-group', (req, res, next) => {

	// Use this endpoint to add one or more users in a group.

	getUserByEmail(req.body.userEmail, (err, data) => {
		const user_id = JSON.parse(data)[0].identities[0].user_id;

		getGroupIdByName(req.body.groupName, (err, data) => {
			const group_id = data;
			
			var options = {
				method: 'PATCH',
				url: process.env.AUTH0_EXTENSION_URL + `/users/${user_id}/groups`,
				headers: {
					'content-type':'application/json',
					authorization: `Bearer ${data.access_token}`
				},
				 // ERROR: No idea how to add group_id in options 
				// https://auth0.com/docs/api/authorization-extension?http#add-user-to-groups
				body: {
					groups:[group_id]
				},
				json: true // This syntax works on update. is method patch the problem???
			};
		
			request(options, function (error, response, body) {
				if (error) throw new Error(error);
				
				console.log(body);
			});
			
		});
	});
	
})

function getAuthExtAPIAccessToken(cb) {
	var options = { 
		method: 'POST',
		url: `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
		headers: { 'content-type':'application/json' },
		body: {
			client_id: process.env.AUTH0_CLIENT_ID,
			client_secret: process.env.AUTH0_CLIENT_SECRET,
			audience:'urn:auth0-authz-api', // only this is different in the 2 token calls
			grant_type:'client_credentials'
		},
		json: true
	};

	request(options, function (error, response, body) {
		if (error) throw new Error(error);
		
		// console.log('getAuthExtAPIAccessToken: ', JSON.parse(body));
		return cb(null, body);
	});
}

function getManagementAPIAccessToken(cb) {
	var options = { 
		method: 'POST',
		url: `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
		headers: { 'content-type':'application/json' },
		body: {
			client_id: process.env.AUTH0_CLIENT_ID,
			client_secret: process.env.AUTH0_CLIENT_SECRET,
			audience:`https://${process.env.AUTH0_DOMAIN}/api/v2/`, // only this is different in the 2 token calls
			grant_type:'client_credentials'
		},
		json: true
	};

	request(options, function (error, response, body) {
		if (error) throw new Error(error);
		
		// console.log('getManagementAPIAccessToken: ', JSON.parse(body));
		return cb(null, body);
	});
}

// Use this endpoint to retrieve all groups.
function getAllGroups(cb) {
	getAuthExtAPIAccessToken((err, data) => {
		var options = { 
			method: 'GET',
			url: process.env.AUTH0_EXTENSION_URL + `/groups`,
			headers: {
				authorization: `Bearer ${data.access_token}`
			}
		};
	
		request(options, function (error, response, body) {
			if (error) throw new Error(error);

			// console.log('getAllGroups: ', JSON.parse(body));
			return cb(null, body);
		});
	});
}

function getGroupIdByName(name, cb) {
	getAllGroups((err, data) => {
		data = JSON.parse(data);
		const result = data.groups.find(obj => obj.name == name);
		return cb(null, result._id);
	})
}

function getUserByEmail(email, cb) {
	getManagementAPIAccessToken((err, data) => {
		var options = {
			method: 'GET',
			url: `https://${process.env.AUTH0_DOMAIN}/api/v2/users-by-email`,
			qs: { email:email },
			headers: { authorization: `Bearer ${data.access_token}`}
		};

		request(options, function (error, response, body) {
			if (error) throw new Error(error);

			// console.log('getUserByEmail: ', JSON.parse(body));
			return cb(null, body);
		});
	});
}

// Use this endpoint to get a single group based on its unique identifier. 
// Add "?expand" to also load all roles and permissions for this group.
function getSingleGroup(group_id, cb) {
	getAuthExtAPIAccessToken((err, data) => {
		var options = { 
			method: 'GET',
			url: process.env.AUTH0_EXTENSION_URL + `/groups/${group_id}`,
			headers: {
				authorization: `Bearer ${data.access_token}`
			}
		};
	
		request(options, function (error, response, body) {
			if (error) throw new Error(error);

			// console.log('getSingleGroup: ', JSON.parse(body));
			return cb(null, body);
		});
	});
}

// Use this endpoint to get the roles for a group.
function getGroupRoles(group_id, cb) {
	getAuthExtAPIAccessToken((err, data) => {
		var options = { 
			method: 'GET',
			url: process.env.AUTH0_EXTENSION_URL + `/groups/${group_id}/roles`,
			headers: {
				authorization: `Bearer ${data.access_token}`
			}
		};
	
		request(options, function (error, response, body) {
			if (error) throw new Error(error);

			// console.log('getGroupRoles: ', JSON.parse(body));
			return cb(null, body);
		});
	});
}

// Use this endpoint to retrieve all roles.
function getAllRoles(cb) {
	getAuthExtAPIAccessToken((err, data) => {
		var options = { 
			method: 'GET',
			url: process.env.AUTH0_EXTENSION_URL + `/roles`,
			headers: {
				authorization: `Bearer ${data.access_token}`
			}
		};
	
		request(options, function (error, response, body) {
			if (error) throw new Error(error);

			// console.log('getAllRoles: ', JSON.parse(body));
			return cb(null, body);
		});
	});
}

// Use this endpoint to update the name or the description of a group.
function updateGroup(group_id, new_name, new_description, cb) {
	getAuthExtAPIAccessToken((err, data) => {
		var options = { 
			method: 'PUT',
			url: process.env.AUTH0_EXTENSION_URL + `/groups/${group_id}`,
			headers: {
				'content-type':'application/json',
				authorization: `Bearer ${data.access_token}`
			},
			body: {
				name: new_name,
				description: new_description
			},
			json: true
		};
	
		request(options, function (error, response, body) {
			if (error) throw new Error(error);

			// console.log('getGroupRoles: ', JSON.parse(body));
			return cb(null, body);
		});
	});
}



// CREATE or ADD -> problem with how to send data 
// READ -> works good
// UPDATE -> works good
// DELETE -> problem with how to send data 

// All functions are repetitve codes, just change options



module.exports = router;
