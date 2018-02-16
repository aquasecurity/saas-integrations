var async = require('async');
var AWS = require('aws-sdk');

var parseArn = function(arn) {
	// Sample: arn:aws:sns:sa-east-1:123456789101:cloudsploit-test
	var arnOne = arn.substring(12);
	return arnOne.substring(0, arnOne.indexOf(':'));
}

var raw = function(topic, params, callback) {
	if (!topic) return callback('No topic provided');
	if (!params) return callback('No params provided');
	if (!params.Message) return callback('No params Message provided');
	if (!params.Subject) return callback('No params Subject provided');
	if (!params.MessageStructure) params.MessageStructure = 'json';
	if (!params.TopicArn) params.TopicArn = topic;

	var sns = new AWS.SNS({region: parseArn(topic)});
	
	sns.publish(params, function(err, data) {
		callback(err);
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

	var payload = {
		default: 'New CloudSploit scan available for account: ' + settings.account_name + ': ' + settings.num_pass + ' PASS; ' + settings.num_warn + ' WARN; ' + settings.num_fail + ' FAIL; ' + settings.num_unknown + ' UNKNOWN; ' + settings.num_new_risks + ' NEW',
		email: 'New CloudSploit scan available for account: ' + settings.account_name + ': ' + settings.num_pass + ' PASS; ' + settings.num_warn + ' WARN; ' + settings.num_fail + ' FAIL; ' + settings.num_unknown + ' UNKNOWN; ' + settings.num_new_risks + ' NEW',
		sms: 'New CloudSploit scan for: ' + settings.account_name + ': ' + settings.num_pass + ' PASS; ' + settings.num_warn + ' WARN; ' + settings.num_fail + ' FAIL; ' + settings.num_unknown + ' UNKNOWN; ' + settings.num_new_risks + ' NEW'
	};

	async.eachLimit(settings.endpoints, 5, function(topic, cb){
		var params = {
			Message: JSON.stringify(payload),
			Subject: 'CloudSploit: New Scan Available'
		};

		raw(topic, params, function(err){
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
		var resourcesMsg = settings.resources.join('\n  ');
	} else {
		var resourcesMsg = 'N/A';
	}

	var msg = 'Connected AWS account: ' + settings.account_name +
			  ' is in a ' + warnOrFail + ' state for the plugin: ' + settings.test_name +
			  '\n\nAccount: ' + settings.account_name +
			  '\nStatus: ' + warnOrFail +
			  '\nPlugin: ' + settings.test_name +
			  '\nAffected Resources:\n  ' + resourcesMsg;

	async.eachLimit(settings.endpoints, 5, function(topic, cb){
		var params = {
			Message: JSON.stringify({
				default: msg,
				email: msg,
				sms: settings.test_name + ' is ' + warnOrFail + ' for ' + settings.account_name
			}),
			Subject: 'CloudSploit: ' + settings.account_name + ': ' + settings.test_name + ' ' + warnOrFail
		};
		
		raw(topic, params, function(err){
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

	var msg = 'Account: ' + settings.account_name +
			  '\nAction: ' + settings.event.action +
			  '\nRegion: ' + settings.event.region +
			  '\nUser: ' + settings.event.caller +
			  '\nIP Address: ' + settings.event.ip_address +
			  '\nMessage: ' + settings.event.message +
			  '\nOriginal Event:\n\n' +
			  JSON.stringify(settings.original, null, 4);

	async.eachLimit(settings.endpoints, 5, function(topic, cb){
		var params = {
			Message: JSON.stringify({
				default: msg,
				email: msg,
				sms: 'Event Alert: account: ' + settings.account_name + ' action: ' + settings.event.action,
			}),
			Subject: 'CloudSploit Event Alert for AWS account: ' + settings.account_name + ' action: ' + settings.event.action
		};
		
		raw(topic, params, function(err){
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