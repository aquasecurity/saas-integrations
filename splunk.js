var async = require('async');
var request = require('request');

var raw = function(endpoint, token, payload, callback) {
	if (!endpoint) return callback('No Splunk endpoint provided');
	if (!token) return callback('No Splunk token provided');
	if (!payload) return callback('No Splunk payload provided');

	request({
	    url: endpoint,
	    method: 'POST',
	    headers: {
	        Authorization: 'Splunk ' + token
	    },
	    json: payload
	}, function(err, response, body){
	    if (err) return callback(err);

	    if (!response || !response.statusCode ) return callback('Invalid response from Splunk');
	    callback();
	});
};

/*
 * results - called to send results for a new scan report
 * arguments:
 *     settings: an object containing the following properties:
 *         - endpoints
 *         - account_name
 *         - num_pass, num_warn, num_fail, num_unknown, num_new_risks
 *     callback
*/
var result = function(settings, callback) {
	if (!settings) return callback('No settings object provided');
	if (!settings.endpoints) return callback('No settings endpoints provided');
	if (!settings.raw_results) return callback('No raw_results provided');

	var payload = {
        'event': settings.raw_results
	};

	async.each(settings.endpoints, function(endpoint, cb){
		// Splunk endpoints are delimited by ":::" such as:
		// endpoint:::token
		// Split them for use with the raw function
		var endpointSplit = endpoint.split(':::');
		var splunkEndpoint = endpointSplit[0];
		var splunkToken = endpointSplit[1];

		if (!splunkEndpoint || !splunkToken) return cb();

		raw(splunkEndpoint, splunkToken, payload, function(err){
			cb(err);
		});
	}, function(err){
		callback(err);
	});
};

/*
 * alert - called to send an alert for a test
 * arguments:
 *     settings: an object containing the following properties:
 *         - endpoints
 *         - account_name
 *         - test_name
 *         - test_description
 *         - result
 *         - scan_id
 *         - resources
 *     callback
*/
var alert = function(settings, callback) {
	if (!settings) return callback('No settings object provided');
	if (!settings.endpoints) return callback('No settings endpoints provided');
	if (!settings.account_name) return callback('No settings account_name provided');
	if (!settings.test_name) return callback('No settings test_name provided');
	if (!settings.test_description) return callback('No settings test_description provided');
	if (!settings.scan_id) return callback('No settings test_description provided');
	if (settings.result !== 1 && settings.result !== 2) return callback('Settings result is not a valid number');

	var warnOrFail = settings.result === 1 ? 'WARN' : 'FAIL';

	if (settings.resources && settings.resources.length) {
		var resourcesMsg = settings.resources.join(', ');
	} else {
		var resourcesMsg = 'N/A';
	}

	var msg = '[' + warnOrFail + '] Connected AWS account: ' + settings.account_name +
			  ' is in a ' + warnOrFail + ' state for the plugin: ' + settings.test_name +
			  '; Account: ' + settings.account_name +
			  '; Status: ' + warnOrFail +
			  '; Plugin: ' + settings.test_name +
			  '; Affected Resources: ' + resourcesMsg;

	var payload = {
        'event': msg
	};

    async.each(settings.endpoints, function(endpoint, cb){
    	// Splunk endpoints are delimited by ":::" such as:
    	// endpoint:::token
    	// Split them for use with the raw function
    	var endpointSplit = endpoint.split(':::');
    	var splunkEndpoint = endpointSplit[0];
    	var splunkToken = endpointSplit[1];

    	if (!splunkEndpoint || !splunkToken) return cb();

    	raw(splunkEndpoint, splunkToken, payload, function(err){
    		cb(err);
    	});
    }, function(err){
    	callback(err);
    });
};

/*
 * event - called to send an event alert routing
 * arguments:
 *     settings: an object containing the following properties:
 *         - endpoints
 *         - account_name
 *         - event
 *         - original
 *     callback
*/
var event = function(settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints) return callback('No settings endpoints provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (!settings.event) return callback('No settings event provided');
    if (!settings.original) return callback('No settings original provided');
    if (settings.event.result !== 1 && settings.event.result !== 2) return callback('Settings event result is not a valid number');

    var warnOrFail = settings.event.result === 1 ? 'WARN' : 'FAIL';

    var msg = '[' + warnOrFail + '] Account: ' + settings.account_name +
    		  '; Action: ' + settings.event.action +
    		  '; Region: ' + settings.event.region +
    		  '; User: ' + settings.event.caller +
    		  '; IP Address: ' + settings.event.ip_address +
    		  '; Message: ' + settings.event.message +
    		  '; Original Event: ' +
    		  JSON.stringify(settings.original);

	var payload = {
        'event': msg
	};

    async.each(settings.endpoints, function(endpoint, cb){
    	// Splunk endpoints are delimited by ":::" such as:
    	// endpoint:::token
    	// Split them for use with the raw function
    	var endpointSplit = endpoint.split(':::');
    	var splunkEndpoint = endpointSplit[0];
    	var splunkToken = endpointSplit[1];

    	if (!splunkEndpoint || !splunkToken) return cb();

    	raw(splunkEndpoint, splunkToken, payload, function(err){
    		cb(err);
    	});
    }, function(err){
    	callback(err);
    });
};

module.exports = {
	raw: raw,
	result: result,
	alert: alert,
	event: event
};
