var async = require('async');
var request = require('request');
var config = {
	SLACK_ICON_URL: 'https://cloudsploit.com/img/logo-small.png',
	SLACK_USERNAME: 'CloudSploit'
};

var raw = function(webhookUrl, payload, callback) {
	if (!webhookUrl) return callback('No webhook URL provided');
	if (!payload) return callback('No payload provided');
	if (!payload.text) return callback('No payload text provided');
	if (!payload.icon_url) payload.icon_url = config.SLACK_ICON_URL;
	if (!payload.username) payload.username = config.SLACK_USERNAME;
	if (!payload.attachments || !payload.attachments.length) return callback('No payload attachments provided');

	request.post(webhookUrl, {form: {
		payload: JSON.stringify(payload)
	}}, function(err, response){
		if (err) return callback(err);

		if (!response || !response.body || response.body !== 'ok') {
			return callback('Invalid response from Slack');
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

	var payload = {
		text: 'A new CloudSploit scan is available for account: ' + settings.account_name + '. <https://console.cloudsploit.com/signin|Click here> to log in.',
		attachments: []
	};

	if (settings.num_pass) {
		payload.attachments.push({
			fallback: 'There were ' + settings.num_pass + ' passing results.',
			color: 'good',
			text: settings.num_pass + ' PASS'
		});
	}

	if (settings.num_warn) {
		payload.attachments.push({
			fallback: 'There were ' + settings.num_warn + ' warning results.',
			color: 'warning',
			text: settings.num_warn + ' WARN'
		});
	}

	if (settings.num_fail) {
		payload.attachments.push({
			fallback: 'There were ' + settings.num_fail + ' failing results.',
			color: 'danger',
			text: settings.num_fail + ' FAIL'
		});
	}

	if (settings.num_unknown) {
		payload.attachments.push({
			fallback: 'There were ' + settings.num_unknown + ' unknown results.',
			color: '#9A9A9A',
			text: settings.num_unknown + ' UNKNOWN'
		});
	}

	if (settings.num_new_risks) {
		payload.attachments.push({
			fallback: 'There were ' + settings.num_new_risks + ' new risk results.',
			color: '#9A9A9A',
			text: settings.num_new_risks + ' NEW'
		});
	}

	// No results to send
	if (!payload.attachments.length) return callback();

	async.each(settings.endpoints, function(webhookUrl, cb){
		raw(webhookUrl, payload, function(err){
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

	var payload = {
		text: 'CloudSploit Alert for test: ' + settings.test_name + ' in account: ' + settings.account_name + ' <https://console.cloudsploit.com/signin|Click here> to log in.',
		attachments: [
			{
				color: settings.result == 1 ? 'warning' : 'danger',
				fields: [
					{
						title: 'Description',
						value: settings.test_description,
						short: false
					},
					{
						title: 'Account',
						value: settings.account_name,
						short: true
					},
					{
						title: 'Priority',
						value: settings.result == 1 ? 'Warning' : 'Failure',
						short: true
					}
				]
			}
		]
	};

	if (settings.resources && settings.resources.length) {
		payload.attachments[0].fields.push({
			title: 'Affected Resources',
			value: settings.resources.join(', '),
			short: false
		});
	}

	async.each(settings.endpoints, function(webhookUrl, cb){
		raw(webhookUrl, payload, function(err){
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

	var payload = {
		text: 'CloudSploit Event Alert for account: ' + settings.account_name + ' <https://console.cloudsploit.com/signin|Click here> to log in.',
		attachments: [
			{
				color: settings.event.result == 1 ? 'warning' : 'danger',
				fields: [
					{
						title: 'Action',
						value: settings.event.action,
						short: true
					},
					{
						title: 'Region',
						value: settings.event.region,
						short: true
					},
					{
						title: 'IP Address',
						value: settings.event.ip_address,
						short: true
					},
					{
						title: 'User',
						value: settings.event.caller,
						short: false
					},
					{
						title: 'Message',
						value: settings.event.message,
						short: false
					}
				]
			}
		]
	};

	async.each(settings.endpoints, function(webhookUrl, cb){
		raw(webhookUrl, payload, function(err){
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