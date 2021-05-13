var async = require('async');
var request = require('request');
var config = {
    ICON_URL: 'https://cloudsploit.com/img/logo-small.png',
    SIGN_IN_URL: 'https://console.cloudsploit.com/signin',
    COLORS: {
        DEFAULT: '172B4D',
        SUCCESS: '1A7F44',
        WARNING: '947E2A',
        DANGER: 'FF0302',
        UNKNOWN: '9A9A9A'
    }
};

var raw = function (webhookUrl, payload, callback) {
    if (!webhookUrl) return callback('No webhook URL provided');
    if (!payload) return callback('No payload provided');
    if (!payload.text) return callback('No payload text provided');
    if (!payload.themeColor) payload.themeColor = config.COLORS.DEFAULT;

    request({
        url: webhookUrl,
        method: 'POST',
        json: payload
    }, function (err, response) {
        if (err) return callback(err);

        if (!response) {
            return callback('Invalid response from Microsoft Teams');
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
var result = function (settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints) return callback('No settings endpoints provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (typeof settings.num_pass !== 'number') return callback('Settings num_pass is not a valid number');
    if (typeof settings.num_warn !== 'number') return callback('Settings num_warn is not a valid number');
    if (typeof settings.num_fail !== 'number') return callback('Settings num_fail is not a valid number');
    if (typeof settings.num_unknown !== 'number') return callback('Settings num_unknown is not a valid number');
    if (typeof settings.num_new_risks !== 'number') return callback('Settings num_new_risks is not a valid number');

    var payload = {
        themeColor: config.COLORS.SUCCESS,
        text: "A new CloudSploit scan is available",
        sections: [{
            activityTitle: "For account: " + settings.account_name,
            activitySubtitle: "[Click here](" + config.SIGN_IN_URL + ") to log in.",
            activityImage: config.ICON_URL,
            facts: []
        }]
    };

    if (settings.num_pass) {
        payload.sections[0].facts.push({
            name: 'PASS',
            text: settings.num_pass
        });
    }

    if (settings.num_warn) {
        payload.sections[0].facts.push({
            name: 'WARN',
            text: settings.num_warn
        });
    }

    if (settings.num_fail) {
        payload.sections[0].facts.push({
            name: 'FAIL',
            text: settings.num_fail
        });
    }

    if (settings.num_unknown) {
        payload.sections[0].facts.push({
            name: 'UNKNOWN',
            text: settings.num_unknown
        });
    }

    if (settings.num_new_risks) {
        payload.sections[0].facts.push({
            name: 'NEW',
            text: settings.num_new_risks
        });
    }

    async.each(settings.endpoints, function (webhookUrl, cb) {
        raw(webhookUrl, payload, function (err) {
            cb(err);
        });
    }, function (err) {
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
var alert = function (settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints) return callback('No settings endpoints provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (!settings.test_name) return callback('No settings test_name provided');
    if (!settings.test_description) return callback('No settings test_description provided');
    if (!settings.scan_id) return callback('No settings test_description provided');
    if (settings.result !== 1 && settings.result !== 2) return callback('Settings result is not a valid number');

    var payload = {
        themeColor: settings.result == 1 ? config.COLORS.WARNING : config.COLORS.DANGER,
        text: "CloudSploit Alert",
        sections: [
            {
                activityTitle: "For account: " + settings.account_name,
                activitySubtitle: "[Click here](" + config.SIGN_IN_URL + ") to log in.",
                activityImage: config.ICON_URL,
                facts: [
                    {
                        name: "Account:",
                        value: settings.account_name
                    },
                    {
                        name: "Priority:",
                        value: settings.result == 1 ? 'Warning' : 'Failure'
                    },
                    {
                        name: "Message:",
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

    async.each(settings.endpoints, function (webhookUrl, cb) {
        raw(webhookUrl, payload, function (err) {
            cb(err);
        });
    }, function (err) {
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
var event = function (settings, callback) {
    if (!settings) return callback('No settings object provided');
    if (!settings.endpoints) return callback('No settings endpoints provided');
    if (!settings.account_name) return callback('No settings account_name provided');
    if (!settings.event) return callback('No settings event provided');
    if (!settings.original) return callback('No settings original provided');
    if (settings.event.result !== 1 && settings.event.result !== 2) return callback('Settings event result is not a valid number');

    var payload = {
        themeColor: settings.result == 1 ? config.COLORS.WARNING : config.COLORS.DANGER,
        text: "CloudSploit Event Alert",
        sections: [{
            activityTitle: "For account: " + settings.account_name,
            activitySubtitle: "[Click here](" + config.SIGN_IN_URL + ") to log in.",
            activityImage: config.ICON_URL,
            facts: [
                {
                    name: "Account:",
                    value: settings.account_name
                },
                {
                    name: "Action:",
                    value: settings.event.action
                },
                {
                    name: "Region:",
                    value: settings.event.region
                },
                {
                    name: "User:",
                    value: settings.event.caller
                },
                {
                    name: "IP Address:",
                    value: settings.event.ip_address
                },
                {
                    name: "Message:",
                    value: settings.event.message
                }
            ]
        }]
    };

    async.each(settings.endpoints, function (webhookUrl, cb) {
        raw(webhookUrl, payload, function (err) {
            cb(err);
        });
    }, function (err) {
        callback(err);
    });
};

module.exports = {
    raw: raw,
    result: result,
    alert: alert,
    event: event
};