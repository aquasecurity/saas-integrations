var async = require('async');
var request = require('request');

var raw = function(apiKey, payload, callback) {
    if (!payload) return callback('No payload provided');
    if (!apiKey.accountId) return callback('No accountId provided');
    if (!apiKey.authString) return callback('No authString provided');
    if (!payload.shortDescription) return callback('Short description is not provided');
    if (!payload.description) return callback('Description is not provided');

    let serviceNowURL = `https://${apiKey.accountId}.service-now.com/api/now/table/`;

    if (apiKey.isSecurityIncident) {
        serviceNowURL = `${serviceNowURL}sn_si_incident`;
    } else {
        serviceNowURL = `${serviceNowURL}incident`;
    }

    request.post({
        url: serviceNowURL,
        method: 'POST',
        headers: {
            'Authorization': 'Basic ' + authString
        },
        data: JSON.stringify(payload)

    }, function(err, response){
        if (err) return callback(err);

        if (!response || !response.body) {
            return callback('Invalid response from Servicenow');
        }

        if (response.status === 201) return callback(response);

        callback(null, response);
    });
};

/*
 * results - called to send results for a new scan report
 * arguments:
 *     settings: an object containing the following properties:
 *         - endpoints -> array of servicenow accounts information
    *          - accountId
    *          - authString
 *         - account_name
 *         - num_pass, num_warn, num_fail, num_unknown, num_new_risks
 *         - isSecurityIncident
 *         - severity
 *     callback
*/
var result = function(settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints && !settings.endpoints.length) return callback('No settings endpoints provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (typeof settings.num_pass !== 'number') return callback('Settings num_pass is not a valid number');
    if (typeof settings.num_warn !== 'number') return callback('Settings num_warn is not a valid number');
    if (typeof settings.num_fail !== 'number') return callback('Settings num_fail is not a valid number');
    if (typeof settings.num_unknown !== 'number') return callback('Settings num_unknown is not a valid number');
    if (typeof settings.num_new_risks !== 'number') return callback('Settings num_new_risks is not a valid number');
    if (typeof settings.severity !== 'number') return callback('Settings severity is not a valid number');
    if (settings.severity !== 1 && settings.severity !== 2 && settings.severity !== 3) return callback('Settings severity is not a valid number');
    if (!settings.isSecurityIncident) return callback('No settings isSecurityIncident provided');

    var description = 'Results: ' + settings.num_pass + ' PASS; ' + settings.num_warn + ' WARN; ' + settings.num_fail + ' FAIL; ' + settings.num_unknown + ' UNKNOWN; ' + settings.num_new_risks + ' NEW';

    var payload = {
        [isSecurityIncident ? 'businessCriticality' : 'impact']: settings.severity,
        [isSecurityIncident ? 'priority' : 'urgency']: settings.severity,
        shortDescription: '[INFO] New Scan for: ' + settings.account_name,
        description
    };

    async.eachLimit(settings.account, 5, function(account, cb){
        var apiKey = {
            accountId: account.accountId,
            authString: account.authString
        };

        raw(apiKey, payload, function(err){
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
 *         - endpoints -> array of servicenow accounts information
 *             - accountId
 *             - authString
 *         - account_name
 *         - test_name
 *         - test_description
 *         - result
 *         - scan_id
 *         - resources
 *         - account_type
 *         - cloud
 *         - isSecurityIncident
 *         - severity
 *     callback
*/
var alert = function(settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints && !settings.endpoints.length) return callback('No settings endpoints provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (!settings.test_name) return callback('No settings test_name provided');
    if (!settings.test_description) return callback('No settings test_description provided');
    if (!settings.scan_id) return callback('No settings test_description provided');
    if (!settings.cloud) return callback('No settings cloud provided');
    if (!settings.account_type) return callback('No settings account type provided');
    if (settings.result !== 1 && settings.result !== 2) return callback('Settings result is not a valid number');
    if (settings.severity !== 1 && settings.severity !== 2 && settings.severity !== 3) return callback('Settings severity is not a valid number');
    if (!settings.isSecurityIncident) return callback('No settings isSecurityIncident provided');

    var description = 'Affected Resources: ' + settings.resources.join(', ');

    var payload = {
        [isSecurityIncident ? 'businessCriticality' : 'impact']: settings.severity,
        [isSecurityIncident ? 'priority' : 'urgency']: settings.severity,
        shortDescription: message,
        description,
    };

    async.eachLimit(settings.accounts, 5, function(account, cb){
        var apiKey = {
            accountId: account.accountId,
            authString: account.authString
        };

        raw(apiKey, payload, function(err){
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
 *         - endpoints -> array of servicenow accounts information
 *             - accountId
 *             - authString
 *         - account_name
 *         - event
 *         - original
 *         - account_type
 *         - cloud
 *         - isSecurityIncident
 *     callback
*/
var event = function(settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints && !settings.endpoints.length) return callback('No settings endpoints provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (!settings.event) return callback('No settings event provided');
    if (!settings.original) return callback('No settings original provided');
    if (!settings.account_type) return callback('No settings account type provided');
    if (settings.event.result !== 1 && settings.event.result !== 2) return callback('Settings event result is not a valid number');
    if (settings.severity !== 1 && settings.severity !== 2 && settings.severity !== 3) return callback('Settings severity is not a valid number');
    if (!settings.isSecurityIncident) return callback('No settings isSecurityIncident provided');

    var payload = {
        [isSecurityIncident ? 'businessCriticality' : 'impact']: settings.severity,
        [isSecurityIncident ? 'priority' : 'urgency']: settings.severity,
        shortDescription: `Aqua Wave CSPM Event Alert for ${settings.cloud} ${settings.account_type}: ${settings.account_name} action: ${settings.event.action}`,
        description: `${settings.account_type}: ` + settings.account_name + '; Action: ' + settings.event.action + '; Region: ' + settings.event.region + '; User: ' + settings.event.caller + '; IP Address: ' + settings.event.ip_address + '; Message: ' + settings.event.message + '; Original: ' + settings.original
    };

    async.eachLimit(settings.endpoints, 5, function(endpoint, cb){
        raw(endpoint, payload, function(err){
            cb(err);
        });
    }, function(err){
        callback(err);
    });
};

var testConnection = function(integration, callback) {
    if (!integration) return callback('No integration object provided');
    if (!integration.servicenow_apikey) return callback('No servicenow api key found');

    var payload = {
        shortDescription: 'Connection test',
        description: 'Testing connection with the servicenow api',
    };

    raw(integration.servicenow_apikey, payload, function(err, result){
        if (err) {
            callback(err);
        } else {
            callback(null, result);
        }
    });
};

module.exports = {
    raw: raw,
    result: result,
    alert: alert,
    event: event,
    testConnection: testConnection
};