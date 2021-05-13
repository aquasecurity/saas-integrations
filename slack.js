var async = require('async');
var request = require('request');
var config = {
    SLACK_ICON_URL: 'https://cloud.aquasec.com/assets/img/aqua_logo.png',
    SLACK_USERNAME: 'Aqua Wave',
    AQUA_CONSOLE_URL: 'https://cloud.aquasec.com'
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

        if (!response || !response.body) {
            return callback('Invalid response from Slack');
        }

        if (response.body !== 'ok') return callback(response);

        callback(null, response);
    });
};

/*
 * results - called to send results for a new scan report
 * arguments:
 *     settings: an object containing the following properties:
 *         - endpoints
 *         - account_name
 *         - account_type
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
    if (!settings.account_type) return callback('No settings account type provided');


    var payload = {
        text: `A new Aqua Wave scan is available for ${settings.account_type}: ` + settings.account_name + '. <https://cloud.aquasec.com/signin|Click here> to log in.',
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
    if (!settings.account_type) return callback('No settings account type provided');
    if (settings.result !== 1 && settings.result !== 2) return callback('Settings result is not a valid number');

    var payload = {
        text: 'Aqua Wave CSPM Alert for test: ' + settings.test_name + ` in ${settings.account_type}: ` + settings.account_name + ' <https://cloud.aquasec.com/signin|Click here> to log in.',
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
                        title: `${settings.account_type}`,
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
    if (!settings.account_type) return callback('No settings account type provided');
    if (settings.event.result !== 1 && settings.event.result !== 2) return callback('Settings event result is not a valid number');

    var payload = {
        text: `Aqua Wave CSPM Event Alert for ${settings.account_type}: ` + settings.account_name + ' <https://cloud.aquasec.com/signin|Click here> to log in.',
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
 *         - account_type
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
    if (!settings.account_type) return callback('No settings account type provided');
    if (settings.result !== 0 && settings.result !== 1) return callback('Settings result is not a valid number');
    if (!settings.created) return callback('No settings created provided');

    var type = (settings.type == 'dryrun') ? 'Dry run: ' : '';
    var verb = (settings.result == 0) ? 'succeeded' : 'failed';
    var verbAction = (settings.event_id) ? 'auto-remediation' : 'manual-remediation';

    var payload = {
        author_icon: config.SLACK_ICON_URL,
        text: type + 'Aqua Wave CSPM ' + verbAction + ' ' + verb + ' (' + settings.remediation_type + `) for ${settings.account_type}: ` + settings.account_name + ' (' + settings.account_id + ')' +
            '\n' + (settings.message ? 'Auto-remediation triggered by event: ' + settings.message : 'Manual remediation triggered via the Aqua CSPM console') +
            '\n <' + config.AQUA_CONSOLE_URL + '/actions?remediation=' + settings.remediation_id + '|Click here to view>',
        attachments: [{
            color: settings.result == 0 ? 'good' : 'danger',
            fields: [
                {
                    title: 'Remediation Detail',
                    value: '',
                    short: false
                },
                {
                    title: `${settings.account_type}:`,
                    value: settings.account_name,
                    short: false
                },
                {
                    title: 'Cloud:',
                    value: settings.cloud.toUpperCase(),
                    short: false
                },
                {
                    title: 'Action:',
                    value: settings.permissions,
                    short: false
                },
                {
                    title: 'Resources:',
                    value: settings.remediated_resources,
                    short: false
                }
            ]
        }]
    };

    if (settings.event_id) {
        let event = [
            {
                title: 'Triggered via Event',
                value: '',
                short: false
            },
            {
                title: 'Region:',
                value: settings.region,
                short: false
            },
            {
                title: 'User:',
                value: settings.caller,
                short: false
            },
            {
                title: 'IP Address:',
                value: settings.ip_address,
                short: false
            },
            {
                title: 'API Call:',
                value: settings.action,
                short: false
            }
        ];

        payload.attachments[0].fields.push(...event);
    }

    async.each(settings.endpoints, function(webhookUrl, cb){
        let integrationName = settings.names[settings.endpoints.indexOf(webhookUrl)];
        raw(webhookUrl, payload, function(err){
            settings.remediation_file['integrations'].push({integration:integrationName, status:(err ? 2 : 0), host:webhookUrl, err:(err ? err : '')});
            cb();
        });
    }, function(err){
        callback(err);
    });
};

var testConnection = function(integration, callback) {
    if (!integration) return callback('No integration object provided');
    if (!integration.slack_webhook_url) return callback('No webhook found');
    var payload = {
        text: 'Aqua Wave Integration Test',
        attachments: [
            {
                fallback: 'Test Successful.',
                color: 'good',
                text: 'PASS'
            }
        ]
    };
    raw(integration.slack_webhook_url, payload, function(err, result){
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