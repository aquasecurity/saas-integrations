var email = require(__dirname + '/../email.js');

var alert = function(settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints) return callback('No settings endpoints provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (!settings.test_name) return callback('No settings test_name provided');
    if (!settings.test_description) return callback('No settings test_description provided');
    if (!settings.scan_id) return callback('No settings scan_id provided');
    if (settings.result !== 1 && settings.result !== 2) return callback('Settings result is not a valid number');

    email.sendAlert(settings.endpoints, settings.account_name, settings.test_name, settings.test_description, settings.result, settings.scan_id, settings.resources, function(err) {
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
    if (settings.event_id) {
        if (!settings.region) return callback('No settings region provided');
        if (!settings.action) return callback('No settings action provided');
        if (!settings.caller) return callback('No settings caller provided');
        if (!settings.ip_address) return callback('No settings ip_address provided');
        if (!settings.message) return callback('No settings message provided');
        if (!settings.created) return callback('No settings created provided');
    }

    email.sendRemediationNotification(settings, function(err) {
        settings.remediation_file['integrations'].push({integration:settings.names, status:(err ? 2 : 0), host:'SMTP', err:(err ? err : '')});
        callback(err);
    });
};

module.exports = {
    alert: alert,
    remediation_notification: remediation_notification
};