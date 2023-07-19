var express = require("express");
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information


/*
 * Add the client information in here
 */
var client = {
	"client_id": "oauth-client-1",
	"client_secret": "oauth-client-secret-1",
	"redirect_uris": ["http://localhost:9000/callback"]
};

var protectedResource = 'http://localhost:9002/resource';

var state = null;

var access_token = null;
var scope = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, scope: scope});
});

app.get('/authorize', function(req, res){

	access_token = null
	state = randomstring.generate()

	var authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
		response_type: 'code',
		client_id: client.client_id, 
		redirect_uri: client.redirect_uris[0],	// The URI for the auth server to send us back to (on the client) once approved or denied
		state: state
	})

	console.log("/authorize")
	res.redirect(authorizeUrl)
});

app.get('/callback', function(req, res){
	console.log("/callback")
	// /authorise on the auth server is called, which returns a response which is a 302 redirect to /callback on the client with 
	// Location: http://localhost:9000/callback?code=MsSm0sY8&state=a9glDJECU7WixsL3DIEG2u13aZdU4VUD
	// a new request is made by the browser to this endpoint
	var code = req.query.code

	// Stop attackers from hitting this endpoint multiple times:
	// E.g. Session fixation attack, fishing for a valid auth code
	if (req.query.state != state) {
		res.render('error', {error: 'State value did not match'})
		return
	}

	// Take this authorization code and send directly to the /token endpoint using an http post 

	var form_data = qs.stringify({
		grant_type: 'authorization_code',
		code: code,
		redirect_uri: client.redirect_uris[0]	// the same redirect must be added to prevent an attacker from using a compromised redirect uri 
	})

	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		// typically Basic base64(username:password). OAuth2 uses base64(id:secret) (with url encoding first)
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)	
	}

	// Get the bearer token and save it down
	var tokRes = request('POST', authServer.tokenEndpoint, {
		body: form_data,
		headers: headers
	})
	var body = JSON.parse(tokRes.getBody())
	console.log(body, body.access_token)
	access_token = body.access_token	// save the access (usually Bearer) token down
	res.render('index', {access_token: access_token})

});

app.get('/fetch_resource', function(req, res) {
	// Cant get resources without an access token
	console.log('fetch_resource', access_token)

	if (!access_token) {
		res.redirect('/authorize')
		return
		res.render('error', { error: 'Missing access token.'})
	}

	// Call resource and had response data off to a page to be rendered
	var headers = {
		'Authorization': 'Bearer ' + access_token
	}
	var resource = request('POST', protectedResource, {headers: headers})

	if (resource.statusCode >= 200 && resource.statusCode <= 300) {
		var body = JSON.parse(resource.getBody())
		res.render('data', {resource: body})
		return
	} else {
		access_token = null;
		res.redirect('/authorize')
		return
		res.render('error', {error: 'sercer returned reponse code: ' + resource.statusCode})
	}
});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

var encodeClientCredentials = function(clientId, clientSecret) {
	return Buffer.from(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
