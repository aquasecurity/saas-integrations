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
    } else {
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
    }, function(err, response){
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

        var results = [];
        var scan_result;

        if (settings.flatten_results) {
            for (var i = 0; i < settings.raw_results.length; i++){
                var testLevel = settings.raw_results[i];

                for (var j = 0; j < testLevel.results.length; j++){
                    var resultLevel = testLevel.results[j];

                    scan_result = {
                        'event': resultLevel,
                        'sourcetype': 'cloudsploit:scan_results'
                    };
                    if (epoch) scan_result.time = epoch;
                    if (settings.account_number) scan_result.event.account_number = settings.account_number;
                    scan_result.event.account_name = settings.account_name;
                    scan_result.event.group_name = settings.group_name;
                    scan_result.event.tags = settings.tags;
                    scan_result.event.cloud = settings.cloud;
                    scan_result.event.category = testLevel.category;
                    scan_result.event.test_id = testLevel.id;
                    scan_result.event.title = testLevel.title;
                    scan_result.event.severity = testLevel.severity;
                    results.push(scan_result);
                }
            }
        } else {
            for (var k = 0; k < settings.raw_results.length; k++){
                scan_result = {
                    'event': settings.raw_results[k],
                    'sourcetype': 'cloudsploit:scan_results'
                };
                if (epoch) scan_result.time = epoch;
                if (settings.account_number) scan_result.event.account_number = settings.account_number;
                scan_result.event.account_name = settings.account_name;
                scan_result.event.group_name = settings.group_name;
                scan_result.event.tags = settings.tags;
                scan_result.event.cloud = settings.cloud;
                scan_result.event.num_pass = settings.num_pass;
                scan_result.event.num_warn = settings.num_warn;
                scan_result.event.num_fail = settings.num_fail;
                scan_result.event.num_unknown = settings.num_unknown;
                scan_result.event.num_new_risks = settings.num_new_risks;
                results.push(scan_result);
            }
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

    var resources = [];
    if (settings.resources && settings.resources.length) {
        resources = settings.resources;
    }

    var event = { 
        'status': warnOrFail,
        'account': settings.account_name,
        'tags': settings.tags,
        'cloud': settings.cloud,
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
    if (epoch) {
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
    if (epoch) {
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
    if (settings.result !== 0 && settings.result !== 1) return callback('Settings result is not a valid number');
    if (!settings.created) return callback('No settings created provided');

    var type = (settings.type == 'dryrun') ? 'Dry run: ' : '';
    var infoOrFail = settings.result == 0 ? 'INFO' : 'FAIL';
    var verb = (settings.result == 0) ? 'succeeded' : 'failed';
    var verbAction = (settings.event_id) ? 'auto-remediation' : 'manual-remediation';
    var message = type + 'Aqua Wave CSPM ' + verbAction + ' ' + verb +  ' for account: ' + settings.account_name + ' (' + settings.account_id + ')' +
        (settings.message ? 'Auto-remediation triggered by event: ' + settings.message : 'Manual remediation triggered via the Aqua CSPM console');

    var event = {
        'severity': infoOrFail,
        'account': settings.account_name,
        'account_id': settings.account_id,
        'cloud': settings.cloud.toUpperCase(),
        'action': settings.permissions,
        'resources': settings.remediated_resources,
        'message': message
    };

    if (settings.event_id) {
        event.region = settings.region;
        event.caller = settings.caller;
        event.ip_address = settings.ip_address;
        event.api_call = settings.action;
    }

    var timestamp = new Date(settings.timestamp);
    var epoch = timestamp.getTime()/1000;

    var payload = {
        'event': event,
        'sourcetype': 'cloudsploit:event'
    };
    if (epoch) {
        payload.time = epoch;
    }

    async.each(settings.endpoints, function(endpoint, cb){
        let integrationName = settings.names[settings.endpoints.indexOf(endpoint)];
        // Splunk endpoints are delimited by ":::" such as:
        // endpoint:::token
        // Split them for use with the raw function
        var endpointSplit = endpoint.split(':::');
        var splunkEndpoint = endpointSplit[0];
        var splunkToken = endpointSplit[1];

        if (!splunkEndpoint || !splunkToken) return cb();

        raw(splunkEndpoint, splunkToken, payload, function(err){
            settings.remediation_file['integrations'].push({integration:integrationName, status:(err ? 2 : 0), host:splunkEndpoint, err:(err ? err : '')});
            cb();
        });
    }, function(err){
        callback(err);
    });

};

var testConnection = function(integration, callback) {
    if (!integration) return callback('No integration object provided');
    if (!integration.splunk_endpoint) return callback('No splunk endpoint found');
    if (!integration.splunk_token) return callback('No splunk token found');
    var payload = {
        'sourcetype': 'cloudsploit:alert',
        'event': {'message':'Access log test message'}
    };
    // var timestamp = new Date();
    // var epoch = timestamp.getTime()/1000;
    //
    // if(epoch) {
    //     payload.time = epoch;
    // }

    raw(integration.splunk_endpoint, integration.splunk_token, payload, function(err, result){
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
    remediation_notification: remediation_notification,
    testConnection: testConnection
};
