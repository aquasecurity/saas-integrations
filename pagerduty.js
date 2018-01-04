var async = require('async');
var request = require('request');
var config = {
	PAGERDUTY_ENDPOINT: 'https://events.pagerduty.com/v2/enqueue'
};

var raw = function(apikey, payload, callback) {
	if (!apikey) return callback('No apikey provided');
	if (!payload) return callback('No payload provided');
	if (!payload.summary) return callback('No payload summary provided');
	if (!payload.source) return callback('No payload source provided');
	if (!payload.severity) return callback('No payload severity provided');
	if (!payload.custom_details) return callback('No payload custom_details provided');

	request.post(config.PAGERDUTY_ENDPOINT, {json: {
	    routing_key: apikey,
	    event_action: 'trigger',
	    payload: payload,
	    client: 'CloudSploit',
	    client_url: 'https://console.cloudsploit.com'
	}}, function(err, response){
	    if (err) return callback(err);
	    if (!response || !response.body ||
	        !response.statusCode || response.statusCode !== 202) {
	        return callback('Invalid response from Pagerduty: ' + JSON.stringify(response));
		}
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
	if (!settings.account_name) return callback('No settings account_name provided');
	if (typeof settings.num_pass !== 'number') return callback('Settings num_pass is not a valid number');
	if (typeof settings.num_warn !== 'number') return callback('Settings num_warn is not a valid number');
	if (typeof settings.num_fail !== 'number') return callback('Settings num_fail is not a valid number');
	if (typeof settings.num_unknown !== 'number') return callback('Settings num_unknown is not a valid number');
	if (typeof settings.num_new_risks !== 'number') return callback('Settings num_new_risks is not a valid number');

	var description = '[INFO] New Scan for: ' + settings.account_name;

	var details = {
	    account: settings.account_name,
	    num_pass: settings.num_pass,
	    num_warn: settings.num_warn,
	    num_fail: settings.num_fail,
	    num_unknown: settings.num_unknown,
	    num_new_risks: settings.num_new_risks
	};

	var payload = {
		summary: description,
		source: details.account,
		severity: 'info',
		custom_details: details
	};

	async.each(settings.endpoints, function(apikey, cb){
		raw(apikey, payload, function(err){
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

	async.each(settings.endpoints, function(apikey, cb){
	    var warnOrFail = settings.result === 1 ? 'WARN' : 'FAIL';
	    var severity = settings.result === 1 ? 'warning' : 'error';
	    var description = '[' + warnOrFail + '] ' + settings.test_name + ' on: ' + settings.account_name;

	    var details = {
	        account: settings.account_name,
	        severity: warnOrFail,
	        plugin: settings.test_name,
	        resources: settings.resources.join(', ')
	    };

	    var payload = {
	    	summary: description,
	    	source: details.account,
	    	severity: severity,
	    	custom_details: details
	    };

	    raw(apikey, payload, function(err){
	    	cb(err);
	    });
	}, function(){
	    callback();
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

	async.eachLimit(settings.endpoints, 5, function(apikey, cb){
		var description = 'CloudSploit Event Alert for AWS account: ' + settings.account_name + ' action: ' + settings.event.action;

		var details = {
			account: settings.account_name,
			severity: settings.event.result,
			action: settings.event.action,
			region: settings.event.region,
			user: settings.event.caller,
			ip_address: settings.event.ip_address,
			message: settings.event.message,
			original: JSON.stringify(settings.original, null, 2)
		};

		var payload = {
			summary: description,
			source: details.account,
			severity: (details.severity === 1) ? 'warning': 'error',
			custom_details: details
		};

		raw(apikey, payload, function(err){
			cb(err);
		});
	}, function(){
		callback();
	});
};

module.exports = {
	raw: raw,
	result: result,
	alert: alert,
	event: event
};