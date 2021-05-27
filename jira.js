var async = require('async');
var https = require('https');

var config = {
    CREATE_ISSUE_PATH: '/rest/api/latest/issue',
    REQUEST_PORT: 443
};

/* Required auguments:
 *     - hostname: Jira account hostname i.e. myaccount.atlassian.net. You can get this from Jira URL
 *     - username: User email needed to call Jira API
 *     - token: User token needed to call Jira API. This token can be generated here: https://id.atlassian.com/manage-profile/security/api-tokens
 *     - project_key: Jira project key such as MP
 *     - issue_type_name: (Optional) Issue type such as Bug, Task, Subtask. Task is set by default
 *     - parent_id: (Optional) Parent issue id. If provided, Subtask will be created
*/

var raw = function(hostname, username, token, payload, callback) {
    if (!hostname) return callback('No base URL provided');
    if (!username) return callback('No username provided');
    if (!token) return callback('No token provided');
    if (!payload) return callback('No payload provided');
    if (!payload.summary) return callback('No payload summary provided');
    if (!payload.projectKey) return callback('No payload project key provided');
    if (!payload.description) return callback('No payload description provided');

    var requestBody = {
        hostname: hostname,
        port: config.REQUEST_PORT,
        path: config.CREATE_ISSUE_PATH,
        method: 'POST',
        headers: {
            'Authorization':'Basic '+Buffer.from(username+':'+token).toString('base64'),
            'Content-Type':'application/json',
        }
    };

    var request = https.request(requestBody, function(response) {
        response.setEncoding('utf8');
        response.on('data', function (body) {
            callback(null, body);
        });
    });
    request.on('error', function(e) {
        callback('Problem with request: ' + e.message);
    });

    var postData = {
        'fields': {
            'project': {
                'key': payload.projectKey
            },
            'issuetype': {
                'name': 'Task',
            },
            'summary': payload.summary,
            'description': payload.description
        }
    };

    if (payload.issueTypeName && ['Task', 'Bug', 'Subtask'].includes(payload.issueTypeName)) {
        postData['fields']['issuetype']['name'] = payload.issueTypeName;
    }

    if (payload.parentId) {
        postData['fields']['parent'] = { 'key': payload.parentId };
        postData['fields']['issuetype']['name'] = 'Subtask';
    }

    var jiraPostString = JSON.stringify(postData);
    request.write(jiraPostString);
    request.end();
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
        summary: 'New CloudSploit scan available for account: ' + settings.account_name + ': ' + settings.num_pass + ' PASS; ' + settings.num_warn + ' WARN; ' + settings.num_fail + ' FAIL; ' + settings.num_unknown + ' UNKNOWN; ' + settings.num_new_risks + ' NEW',
        description: 'New CloudSploit scan for: ' + settings.account_name + ': ' + settings.num_pass + ' PASS; ' + settings.num_warn + ' WARN; ' + settings.num_fail + ' FAIL; ' + settings.num_unknown + ' UNKNOWN; ' + settings.num_new_risks + ' NEW'
    };

    async.eachLimit(settings.endpoints, 5, function(host, cb){
        var hostname = host.hostname;
        var username  = host.username;
        var token  = host.token;
        payload['projectKey'] = host.project_key;
        payload['parentId'] = (host.parent_id) ? host.parent_id : null;

        raw(hostname, username, token, payload, function(err){
            cb(err);
        });
    }, function(err){
        callback(err);
    });
};

// var endpoints = [
//     {
//         hostname: 'akhtar-aqua.atlassian.net',
//         username: 'makhtar.pucit@gmail.com',
//         token: 'yQNFpDHj534yIjGaHkEs3C36',
//         project_key: 'AQ',
//         issue_type_name: 'Task'
//     },
//     {
//         hostname: 'akhtar-aqua.atlassian.net',
//         username: 'makhtar.pucit@gmail.com',
//         token: 'yQNFpDHj534yIjGaHkEs3C36',
//         project_key: 'AC',
//         issue_type_name: 'Subtask',
//         parent_id: 'AC-4'
//     }
// ];

// result({endpoints: endpoints, account_name: 'akhtar-project', num_fail: 20, num_pass: 50, num_warn: 10, num_unknown: 0, num_new_risks: 5}, (err) => {
//     if (err) console.log(err);
//     else console.log('success');
// });

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
        description: 'Aqua Wave CSPM Alert for test: ' + settings.test_name + ` in ${settings.account_type}: ` + settings.account_name,
        summary: 'Affected Resources: ' + settings.resources.join(', ')
    };

    async.each(settings.endpoints, function(host, cb){
        var hostname = host.hostname;
        var username  = host.username;
        var token  = host.token;
        payload['projectKey'] = host.project_key;
        payload['parentId'] = (host.parent_id) ? host.parent_id : null;

        raw(hostname, username, token, payload, function(err){
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
    if (!settings.cloud) return callback('No settings cloud provided');
    if (settings.event.result !== 1 && settings.event.result !== 2) return callback('Settings event result is not a valid number');

    var payload = {
        summary: `CloudSploit Event Alert for ${settings.cloud} ${settings.account_type}: ` + settings.account_name + ' action: ' + settings.event.action,
        description: `${settings.account_type}: ` + settings.account_name +
            '\nAction: ' + settings.event.action +
            '\nRegion: ' + settings.event.region +
            '\nUser: ' + settings.event.caller +
            '\nIP Address: ' + settings.event.ip_address +
            '\nMessage: ' + settings.event.message +
            '\nOriginal Event:\n\n' +
            JSON.stringify(settings.original, null, 4)
    };

    async.eachLimit(settings.endpoints, 5, function(host, cb){
        var hostname = host.hostname;
        var username  = host.username;
        var token  = host.token;
        payload['projectKey'] = host.project_key;
        payload['parentId'] = (host.parent_id) ? host.parent_id : null;

        raw(hostname, username, token, payload, function(err){
            cb(err);
        });
    }, function(err){
        callback(err);
    });
};

var testConnection = function(integration, callback) {
    if (!integration) return callback('No integration object provided');
    if (!integration.hostname) return callback('No hostname found');
    if (!integration.username) return callback('No username found');
    if (!integration.token) return callback('No token found');
    if (!integration.project_key) return callback('No project key found');

    var payload = {
        summary: 'Cloudsploit - Connection test',
        description: 'Cloudsploit - Connection test',
        projectKey: integration.project_key
    };

    if (integration.parent_id) payload['parentId'] = integration.parent_id;

    raw(integration.hostname, integration.username, integration.token, payload, function(err, result){
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