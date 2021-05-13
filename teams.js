var async = require('async');
var request = require('request');
var config = {
    ICON_URL: 'https://cloud.aquasec.com/assets/img/aqua_logo.png',
    SIGN_IN_URL: 'https://cloud.aquasec.com/signin',
    AQUA_CONSOLE_URL: 'https://cloud.aquasec.com',
    COLORS: {
        DEFAULT: '172B4D',
        SUCCESS: '1A7F44',
        WARNING: '947E2A',
        DANGER: 'FF0302',
        UNKNOWN: '9A9A9A'
    }
};

var raw = function(webhookUrl, payload, callback) {
    if (!webhookUrl) return callback('No webhook URL provided');
    if (!payload) return callback('No payload provided');
    if (!payload.text) return callback('No payload text provided');
    if (!payload.themeColor) payload.themeColor = config.COLORS.DEFAULT;

    request({
        url: webhookUrl,
        method: 'POST',
        json: payload
    }, function(err, response) {
        if (err) return callback(err);

        if (!response) {
            return callback('Invalid response from Microsoft Teams');
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
 *         - account_type
 *     callback
*/
var result = function(settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints) return callback('No settings endpoints provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (!settings.account_type) return callback('No settings account type provided');
    if (typeof settings.num_pass !== 'number') return callback('Settings num_pass is not a valid number');
    if (typeof settings.num_warn !== 'number') return callback('Settings num_warn is not a valid number');
    if (typeof settings.num_fail !== 'number') return callback('Settings num_fail is not a valid number');
    if (typeof settings.num_unknown !== 'number') return callback('Settings num_unknown is not a valid number');
    if (typeof settings.num_new_risks !== 'number') return callback('Settings num_new_risks is not a valid number');

    var payload = {
        themeColor: config.COLORS.SUCCESS,
        text: 'A new Aqua Wave CSPM scan is available',
        sections: [{
            activityTitle: `For ${settings.account_type}: ` + settings.account_name,
            activitySubtitle: '[Click here](' + config.SIGN_IN_URL + ') to log in.',
            activityImage: config.ICON_URL,
            facts: []
        }]
    };

    if (settings.num_pass) {
        payload.sections[0].facts.push({
            name: 'PASS',
            value: settings.num_pass
        });
    }

    if (settings.num_warn) {
        payload.sections[0].facts.push({
            name: 'WARN',
            value: settings.num_warn
        });
    }

    if (settings.num_fail) {
        payload.sections[0].facts.push({
            name: 'FAIL',
            value: settings.num_fail
        });
    }

    if (settings.num_unknown) {
        payload.sections[0].facts.push({
            name: 'UNKNOWN',
            value: settings.num_unknown
        });
    }

    if (settings.num_new_risks) {
        payload.sections[0].facts.push({
            name: 'NEW',
            value: settings.num_new_risks
        });
    }

    async.each(settings.endpoints, function(webhookUrl, cb) {
        raw(webhookUrl, payload, function(err) {
            cb(err);
        });
    }, function(err) {
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
        themeColor: settings.result == 1 ? config.COLORS.WARNING : config.COLORS.DANGER,
        text: 'Aqua Wave CSPM Alert',
        sections: [
            {
                activityTitle: 'For account: ' + settings.account_name,
                activitySubtitle: '[Click here](' + config.SIGN_IN_URL + ') to log in.',
                activityImage: config.ICON_URL,
                facts: [
                    {
                        name: 'Account:',
                        value: settings.account_name
                    },
                    {
                        name: 'Priority:',
                        value: settings.result == 1 ? 'Warning' : 'Failure'
                    },
                    {
                        name: 'Plugin:',
                        value: settings.test_name
                    },
                    {
                        name: 'Message:',
                        value: settings.test_description
                    }
                ]
            }
        ]
    };

    if (settings.resources && settings.resources.length) {
        payload.sections[0].facts.push({
            name: 'Affected Resources',
            value: settings.resources.join(', ')
        });
    }

    async.each(settings.endpoints, function(webhookUrl, cb) {
        raw(webhookUrl, payload, function(err) {
            cb(err);
        });
    }, function(err) {
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
        themeColor: settings.result == 1 ? config.COLORS.WARNING : config.COLORS.DANGER,
        text: 'Aqua Wave CSPM Event Alert',
        sections: [{
            activityTitle: `For ${settings.account_type}: ` + settings.account_name,
            activitySubtitle: '[Click here](' + config.SIGN_IN_URL + ') to log in.',
            activityImage: config.ICON_URL,
            facts: [
                {
                    name: `${settings.account_type}:`,
                    value: settings.account_name
                },
                {
                    name: 'Action:',
                    value: settings.event.action
                },
                {
                    name: 'Region:',
                    value: settings.event.region
                },
                {
                    name: 'User:',
                    value: settings.event.caller
                },
                {
                    name: 'IP Address:',
                    value: settings.event.ip_address
                },
                {
                    name: 'Message:',
                    value: settings.event.message
                }
            ]
        }]
    };

    async.each(settings.endpoints, function(webhookUrl, cb) {
        raw(webhookUrl, payload, function(err) {
            cb(err);
        });
    }, function(err) {
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
    if (!settings.account_type) return callback('No settings account type provided');
    if (settings.result !== 0 && settings.result !== 1) return callback('Settings result is not a valid number');
    if (!settings.created) return callback('No settings created provided');

    var type = (settings.type == 'dryrun') ? 'Dry run: ' : '';
    var verb = (settings.result == 0) ? 'succeeded' : 'failed';
    var verbAction = (settings.event_id) ? 'auto-remediation' : 'manual-remediation';

    var payload = {
        themeColor: settings.result == 0 ? config.COLORS.SUCCESS : config.COLORS.DANGER,
        text: type + 'Aqua Wave CSPM ' + verbAction + ' ' + verb +
            ` for ${settings.account_type}: ` + settings.account_name + ' (' + settings.account_id + ')',
        sections: [{
            activityTitle: (settings.message ? 'Auto-remediation triggered by event: ' + settings.message : 'Manual remediation triggered via the Aqua CSPM console'),
            activitySubtitle: '[Click here to view](' + config.AQUA_CONSOLE_URL + '/actions?remediation=' + settings.remediation_id + ')',
            activityImage: config.ICON_URL,
            facts: [
                {
                    name: 'Remediation Detail',
                    value: ''
                },
                {
                    name: `${settings.account_type}:`,
                    value: settings.account_name
                },
                {
                    name: 'Cloud:',
                    value: settings.cloud.toUpperCase()
                },
                {
                    name: 'Action:',
                    value: settings.permissions
                },
                {
                    name: 'Resources:',
                    value: settings.remediated_resources
                }
            ]
        }]
    };

    if (settings.event_id) {
        let event = [
            {
                name: 'Triggered via Event',
                value: ''
            },
            {
                name: 'Region:',
                value: settings.region
            },
            {
                name: 'User:',
                value: settings.caller
            },
            {
                name: 'IP Address:',
                value: settings.ip_address
            },
            {
                name: 'API Call:',
                value: settings.action
            }
        ];

        payload.sections[0].facts.push(...event);
    }

    async.each(settings.endpoints, function(webhookUrl, cb) {
        let integrationName = settings.names[settings.endpoints.indexOf(webhookUrl)];
        raw(webhookUrl, payload, function(err) {
            settings.remediation_file['integrations'].push({integration:integrationName, status:(err ? 2 : 0), host:webhookUrl, err:(err ? err : '')});
            cb();
        });
    }, function(err) {
        callback(err);
    });
};

var testConnection = function(integration, callback) {
    if (!integration) return callback('No integration object provided');
    if (!integration.teams_webhook_url) return callback('No webhook found');
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
    raw(integration.teams_webhook_url, payload, function(err, result){
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