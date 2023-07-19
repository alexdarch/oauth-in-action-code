var express = require("express");
var bodyParser = require('body-parser');
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var __ = require('underscore');
var cors = require('cors');

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

var resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};

/**
 * 
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 */
var getAccessToken = function(req, res, next) {

	var inToken = null
	
	// bearer token in headers (best + most versatile)
	var auth = req.headers['authorization']  // expressjs automatically .tolower()'s all incoming headers
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		inToken = auth.slice('bearer '.length)
	} 
	// token in form-encoded parameters in http body (bad as artifically limits the input api to a form-encoded set of values)
	else if (req.body && req.body.access_token) {
		inToken = req.body.access_token
	}
	// token in query parameter (bad as token is likely to be logged in server access logs or leaked through referrer headers)
	else if (req.query && req.query.access_token) {
		inToken = req.query.access_token
	}

	// Validate the token against our datastore
	console.log('Incoming token: %s', inToken);
	nosql.one().make(function(builder) {
	  builder.where('access_token', inToken);
	  // Call when either a match is found, or the database is exhausted
	  builder.callback(function(err, token) {
	    if (token) {
	      console.log("We found a matching token: %s", inToken);
	    } else {
	      console.log('No matching token was found.');
	    };
	    req.access_token = token;  // Attach token to request object even if we didnt find one and token is null
	    next();
	    return;
	  });
	});

};

app.options('/resource', cors());


app.all('*', getAccessToken) // intercept and run before all endpoints

app.post("/resource", cors(), function(req, res){

	if (req.access_token) {
		res.json(resource)
	} else {
		res.status(401).end()
	}
});

var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
 
