var async = require('async');
var AWS = require('aws-sdk');
var config = {
    AQUA_CONSOLE_URL: 'https://cloud.aquasec.com'
};

var parseArn = function(arn) {
    // Sample: arn:aws:sns:sa-east-1:123456789101:cloudsploit-test
    var arnOne = arn.substring(12);
    return arnOne.substring(0, arnOne.indexOf(':'));
};

var raw = function(topic, params, callback) {
    if (!topic) return callback('No topic provided');
    if (!params) return callback('No params provided');
    if (!params.Message) return callback('No params Message provided');
    if (!params.Subject) return callback('No params Subject provided');
    if (!params.MessageStructure) params.MessageStructure = 'json';
    if (!params.TopicArn) params.TopicArn = topic;

    var sns = new AWS.SNS({region: parseArn(topic)});
    
    sns.publish(params, function(err, data) {
        if (err) return callback(err);
        if (!data) return callback('Invalid response from AWS');
        callback(null, data);
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
 *         - account_type
 *         - cloud
 *     callback
*/
var alert = function(settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints) return callback('No settings endpoints provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (!settings.test_name) return callback('No settings test_name provided');
    if (!settings.test_description) return callback('No settings test_description provided');
    if (!settings.scan_id) return callback('No settings test_description provided');
    if (!settings.cloud) return callback('No settings cloud provided');
    if (!settings.account_type) return callback('No settings account type provided');
    if (settings.result !== 1 && settings.result !== 2) return callback('Settings result is not a valid number');

    var warnOrFail = settings.result === 1 ? 'WARN' : 'FAIL';
    var resourcesMsg;

    if (settings.resources && settings.resources.length) {
        resourcesMsg = settings.resources.join('\n  ');
    } else {
        resourcesMsg = 'N/A';
    }

    var msg = `Connected ${settings.cloud} ${settings.account_type}: ` + settings.account_name +
              ' is in a ' + warnOrFail + ' state for the plugin: ' + settings.test_name +
              `\n\n${settings.account_type}: ` + settings.account_name +
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
 *         - account_type
 *         - cloud
 *     callback
*/
var event = function(settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints) return callback('No settings endpoints provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (!settings.event) return callback('No settings event provided');
    if (!settings.original) return callback('No settings original provided');
    if (!settings.account_type) return callback('No settings account type provided');
    if (settings.event.result !== 1 && settings.event.result !== 2) return callback('Settings event result is not a valid number');

    var msg = `${settings.account_type}: ` + settings.account_name +
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
                sms: `Event Alert: ${settings.account_type}: ` + settings.account_name + ' action: ' + settings.event.action,
            }),
            Subject: `CloudSploit Event Alert for ${settings.cloud} ${settings.account_type}: ` + settings.account_name + ' action: ' + settings.event.action
        };
        
        raw(topic, params, function(err){
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

    var msg = type + 'Aqua Wave CSPM ' + verbAction + ' ' + verb +
        `\nFor ${settings.account_type}: ` + settings.account_name + ' (' + settings.account_id + ')' +
        '\n\nClick here to view: ' + config.AQUA_CONSOLE_URL + '/actions?remediation=' + settings.remediation_id +
        '\n\n' + (settings.message ? 'Auto-remediation triggered by event: ' + settings.message : 'Manual remediation triggered via the Aqua CSPM console') +
        '\nRemediation Detail' +
        `\n${settings.account_type}:` + settings.account_name +
        '\nCloud:' + settings.cloud.toUpperCase() +
        '\nAction:' + settings.permissions +
        '\nResources:' + settings.remediated_resources;

    var sms = 'Aqua Wave CSPM ' + verbAction + ' ' + verb +
        `\nFor ${settings.account_type}: ` + settings.account_name + ' (' + settings.account_id + ')' +
        '\nClick here to view: ' + config.AQUA_CONSOLE_URL + '/actions?remediation=' + settings.remediation_id +
        '\n\n' + (settings.message ? 'Auto-remediation triggered by event: ' + settings.message : 'Manual remediation triggered via the Aqua CSPM console');

    if (settings.event_id) {
        msg = msg.concat('\nTriggered via Event' +
                        '\nRegion:' + settings.region +
                        '\nUser:' + settings.caller +
                        '\nIP Address:' + settings.ip_address +
                        '\nAPI Call:' + settings.action);
    }

    async.eachLimit(settings.endpoints, 5, function(topic, cb){
        let integrationName = settings.names[settings.endpoints.indexOf(topic)];
        var params = {
            Message: JSON.stringify({
                default: msg,
                email: msg,
                sms: sms
            }),
            Subject: 'Aqua Wave CSPM ' + verbAction + ' ' + verb + ' ' + settings.account_name + ' (' + settings.account_id + ')'
        };

        raw(topic, params, function(err){
            settings.remediation_file['integrations'].push({integration:integrationName, status:(err ? 2 : 0), host:topic, err:(err ? err : '')});
            cb();
        });
    }, function(err){
        callback(err);
    });
};

var testConnection = function(integration, callback) {
    if (!integration) return callback('No integration object provided');
    if (!integration.sns_arn) return callback('No endpoint found');
    var payload = {
        Message: JSON.stringify({
            default: 'Connection Test',
            email: 'Connection Test',
            sms: 'Connection Test'
        }),
        Subject: 'CloudSploit: Connection Test'
    };
    raw(integration.sns_arn, payload, function(err, result){
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