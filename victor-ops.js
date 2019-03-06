var async = require('async');
var request = require('request');
var config = {
    VICTOR_OPS_MESSAGE_TYPES: ['INFO', 'WARNING', 'CRITICAL']
};

var raw = function (webhookUrl, payload, callback) {
    if (!webhookUrl) return callback('No webhook URL provided');
    if (!payload) return callback('No payload provided');
    if (!payload.message_type) return callback('No payload message type provided');
    if (!payload.entity_display_name) return callback('No payload entity display name provided');
    if (config.VICTOR_OPS_MESSAGE_TYPES.indexOf(payload.message_type) === -1) return callback('Payload message type is invalid');
    if (!payload.state_message) return callback('No payload state message provided');

    request({
        url: webhookUrl,
        method: 'POST',
        json: payload
    }, function (err, response) {
        if (err) return callback(err);
        callback()
    })
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

var result = function (settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints) return callback('No settings endpoints provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (typeof settings.num_pass !== 'number') return callback('Settings num_pass is not a valid number');
    if (typeof settings.num_warn !== 'number') return callback('Settings num_warn is not a valid number');
    if (typeof settings.num_fail !== 'number') return callback('Settings num_fail is not a valid number');
    if (typeof settings.num_unknown !== 'number') return callback('Settings num_unknown is not a valid number');
    if (typeof settings.num_new_risks !== 'number') return callback('Settings num_new_risks is not a valid number');

    var message = '[INFO] New Scan for: ' + settings.account_name;
    var description = 'Results: ' + settings.num_pass + ' PASS; ' + settings.num_warn + ' WARN; ' + settings.num_fail + ' FAIL; ' + settings.num_unknown + ' UNKNOWN; ' + settings.num_new_risks + ' NEW';

    var payload = {
        message_type: config.VICTOR_OPS_MESSAGE_TYPES[0],
        entity_display_name: message,
        state_message: description
    };

    async.each(settings.endpoints, function (webhookUrl, cb) {
        raw(webhookUrl, payload, function (err) {
            cb(err)
        })
    }, function (err) {
        callback(err)
    })
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

var alert = function (settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints) return callback('No settings endpoints provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (!settings.test_name) return callback('No settings test_name provided');
    if (!settings.test_description) return callback('No settings test_description provided');
    if (!settings.scan_id) return callback('No settings test_description provided');
    if (settings.result !== 1 && settings.result !== 2) return callback('Settings result is not a valid number');

    async.each(settings.endpoints, function (webhookUrl, cb) {
        var warnOrFail = settings.result === 1 ? 'WARN' : 'FAIL';
        var type = settings.result === 1 ? config.VICTOR_OPS_MESSAGE_TYPES[1] : config.VICTOR_OPS_MESSAGE_TYPES[2];
        var message = '[' + warnOrFail + '] ' + settings.test_name + ' on: ' + settings.account_name;
        var description = 'Affected Resources: ' + settings.resources.join(', ');

        var payload = {
            message_type: type,
            entity_display_name: message,
            state_message: description
        };

        raw(webhookUrl, payload, function (err) {
            cb(err)
        })
    }, function (err) {
        callback(err)
    })
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

var event = function (settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints) return callback('No settings endpoints provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (!settings.event) return callback('No settings event provided');
    if (!settings.original) return callback('No settings original provided');
    if (settings.event.result !== 1 && settings.event.result !== 2) return callback('Settings event result is not a valid number');

    async.eachLimit(settings.endpoints, 5, function (webhookUrl, cb) {
        var type = settings.result === 1 ? config.VICTOR_OPS_MESSAGE_TYPES[1] : config.VICTOR_OPS_MESSAGE_TYPES[2];
        var message = 'CloudSploit Event Alert for AWS account: ' + settings.account_name + ' action: ' + settings.event.action;
        var description = 'Account: ' + settings.account_name +
            '; Action: ' + settings.event.action +
            '; Region: ' + settings.event.region +
            '; User: ' + settings.event.caller +
            '; IP Address: ' + settings.event.ip_address +
            '; Message: ' + settings.event.message;

        var payload = {
            message_type: type,
            entity_display_name: message,
            state_message: description
        };

        raw(webhookUrl, payload, function (err) {
            cb(err)
        });

    }, function (err) {
        callback(err)
    })
};

module.exports = {
    raw: raw,
    result: result,
    alert: alert,
    event: event
};
