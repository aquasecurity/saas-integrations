var async = require('async');
var request = require('request');
var config = {
    PAGERDUTY_ENDPOINT: 'https://events.pagerduty.com/v2/enqueue',
    AQUA_CONSOLE_URL: 'https://cloud.aquasec.com'
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
        client: 'Aqua Wave',
        client_url: 'https://cloud.aquasec.com'
    }}, function(err, response){
        if (err) return callback(err);
        if (!response || !response.body ||
            !response.statusCode || response.statusCode !== 202) {
            return callback('Invalid response from Pagerduty: ' + JSON.stringify(response));
        }

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
 *         - account_type
 *         - cloud
 *         - original
 *     callback
*/
var event = function(settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints) return callback('No settings endpoints provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (!settings.event) return callback('No settings event provided');
    if (!settings.original) return callback('No settings original provided');
    if (!settings.cloud) return callback('No settings cloud provided');
    if (!settings.account_type) return callback('No settings account type provided');
    if (settings.event.result !== 1 && settings.event.result !== 2) return callback('Settings event result is not a valid number');

    async.eachLimit(settings.endpoints, 5, function(apikey, cb){
        var description = `Aqua Wave CSPM Event Alert for ${settings.cloud} ${settings.account_type}: ` + settings.account_name + ' action: ' + settings.event.action;


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

/*
 * remediation_notification - called to send a remediation notification
 * arguments:
 *     settings: an object containing the following properties:
 *         - endpoints
 *         - cloud
 *         - account_id
 *         - account_name
 *         - remediated_resources
 *         - remediation_type
 *         - permissions
 *         - remediation_id
 *         - esult
 *         - caller
 *         - region
 *         - action
 *         - ip_address
 *         - message
 *         - created
 *         - account_type
 *     callback
*/
var remediation_notification = function(settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints) return callback('No settings endpoints provided');
    if (!settings.names) return callback('No settings names provided');
    if (!settings.cloud) return callback('No settings cloud provided');
    if (!settings.account_id) return callback('No settings account_id provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (!settings.remediated_resources) return callback('No settings remediated resources provided');
    if (!settings.remediation_type) return callback('No settings remediation type provided');
    if (!settings.permissions) return callback('No settings permissions provided');
    if (!settings.remediation_id) return callback('No settings remediation_id provided');
    if (!settings.account_type) return callback('No settings account type provided');
    if (settings.result !== 0 && settings.result !== 1) return callback('Settings result is not a valid number');
    if (!settings.created) return callback('No settings created provided');

    var type = (settings.type == 'dryrun') ? 'Dry run: ' : '';
    var verb = (settings.result == 0) ? 'succeeded' : 'failed';
    var verbAction = (settings.event_id) ? 'auto-remediation' : 'manual-remediation';
    var severity = (settings.result == 0) ? 'info' : 'error';

    async.eachLimit(settings.endpoints,5, function(apikey, cb){
        let integrationName = settings.names[settings.endpoints.indexOf(apikey)];
        var description = type + 'Aqua Wave CSPM ' + verbAction + ' ' + verb +  ` for ${settings.account_type}: ` + settings.account_name + ' (' + settings.account_id + ')' +
            '\n' + (settings.message ? 'Auto-remediation triggered by event: ' + settings.message : 'Manual remediation triggered via the Aqua CSPM console');

        var details = {
            account: settings.account_name,
            cloud: settings.cloud.toUpperCase(),
            action: settings.permissions,
            resources: settings.remediated_resources,
            link: config.AQUA_CONSOLE_URL + '/actions?remediation=' + settings.remediation_id
        };

        if (settings.event_id) {
            Object.assign(details, {
                region: settings.event.region,
                user: settings.event.caller,
                ip_address: settings.event.ip_address,
                api_call: settings.event.action
            });
        }

        var payload = {
            summary: description,
            source: details.account,
            severity: severity,
            custom_details: details
        };

        raw(apikey, payload, function(err){
            settings.remediation_file['integrations'].push({integration:integrationName, status:(err ? 2 : 0), host:config.PAGERDUTY_ENDPOINT, err:(err ? err : '')});
            cb();
        });
    }, function(err){
        callback(err);
    });
};

var testConnection = function(integration, callback) {
    if (!integration) return callback('No integration object provided');
    if (!integration.pagerduty_apikey) return callback('No pagerduty api key found');
    var payload = {
        summary: 'Connection Test',
        source: 'Aqua Wave',
        severity: 'info',
        custom_details: 'Testing Connection'
    };
    raw(integration.pagerduty_apikey, payload, function(err, result){
        if (err) {
            callback(err, null);
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
    remediation_notification: remediation_notification,
    testConnection: testConnection
};