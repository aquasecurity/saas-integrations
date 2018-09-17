var async = require('async');
var request = require('request');

var raw = function(endpoint, token, payload, callback) {
	if (!endpoint) return callback('No Splunk endpoint provided');
	if (!token) return callback('No Splunk token provided');
	if (!payload) return callback('No Splunk payload provided');

    var payloadStr = '';
    if (Array.isArray(payload)) {
        for (var i = 0; i < payload.length; i++){
            payloadStr += JSON.stringify(payload[i]);
        }
    }
    else {
        payloadStr = JSON.stringify(payload);
    }

	request({
	    url: endpoint,
	    method: 'POST',
	    headers: {
	        'Authorization': 'Splunk ' + token,
            'Content-type': 'application/json' 
	    },
	    body: payloadStr
	}, function(err, response, body){
	    if (err) return callback(err);

	    if (!response || !response.statusCode ) return callback('Invalid response from Splunk');
	    callback(null, response);
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
	if (!settings.account_name) return callback('No account_name provided');
	if (typeof settings.num_pass !== 'number') return callback('Settings num_pass is not a valid number');
    if (typeof settings.num_warn !== 'number') return callback('Settings num_warn is not a valid number');
    if (typeof settings.num_fail !== 'number') return callback('Settings num_fail is not a valid number');
    if (typeof settings.num_unknown !== 'number') return callback('Settings num_unknown is not a valid number');
    if (typeof settings.num_new_risks !== 'number') return callback('Settings num_new_risks is not a valid number');

	async.each(settings.endpoints, function(endpoint, cb){
		// Splunk endpoints are delimited by ":::" such as:
		// endpoint:::token
		// Split them for use with the raw function
		var endpointSplit = endpoint.split(':::');
		var splunkEndpoint = endpointSplit[0];
		var splunkToken = endpointSplit[1];

		if (!splunkEndpoint || !splunkToken) return cb();

        var timestamp = new Date(settings.timestamp);
        var epoch = timestamp.getTime()/1000;

        results = []
        for (var i = 0; i < settings.raw_results.length; i++){
            var scan_result = {
                'event': settings.raw_results[i],
                'sourcetype': 'cloudsploit:scan_results'
            };
            if(epoch){
                scan_result.time = epoch;
            }
            scan_result.event.account_name = settings.account_name;
            scan_result.event.num_pass = settings.num_pass;
            scan_result.event.num_warn = settings.num_warn;
            scan_result.event.num_fail = settings.num_fail;
            scan_result.event.num_unknown = settings.num_unknown;
            scan_result.event.num_new_risks = settings.num_new_risks;
            results.push(scan_result);
        }
        raw(splunkEndpoint, splunkToken, results, function(err){
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
	if (!settings.scan_id) return callback('No settings scan_id provided');
	if (settings.result !== 1 && settings.result !== 2) return callback('Settings result is not a valid number');

	var warnOrFail = settings.result === 1 ? 'WARN' : 'FAIL';

	if (settings.resources && settings.resources.length) {
		var resources = settings.resources;
	} else {
		var resources = [];
	}

    var event = { 
        'status': warnOrFail,
        'account': settings.account_name,
        'plugin': settings.test_name,
        'affected_resources': resources,
        'test_description': settings.test_description,
        'scan_id': settings.scan_id};

    var timestamp = new Date(settings.timestamp);
    var epoch = timestamp.getTime()/1000;

	var payload = {
        'event': event,
        'sourcetype': 'cloudsploit:alert'
	};
    if(epoch) {
        payload.time = epoch;
    }

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
    
    var event = { 
        'severity': warnOrFail,
        'account': settings.account_name,
        'region': settings.event.region,
        'user': settings.event.caller,
        'ip_address': settings.event.ip_address,
        'message': settings.event.message,
        'original_event': settings.original};
    
    var timestamp = new Date(settings.timestamp);
    var epoch = timestamp.getTime()/1000;

	var payload = {
        'event': event,
        'sourcetype': 'cloudsploit:event'
	};
    if(epoch) {
        payload.time = epoch;
    }

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
