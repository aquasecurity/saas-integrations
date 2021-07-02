var async = require('async');
var request = require('request');
var fs = require('fs');

var raw = function(apikey, connector_id, endpoint, payload, callback) {
    if (!apikey) return callback('No apikey provided');
    if (!payload) return callback('No payload provided');

    fs.writeFile('/tmp/kdi_file.json', JSON.stringify(payload), function(){
        const formData = {
            file: fs.createReadStream('/tmp/kdi_file.json'),
            run: 'true'
        };

        var hostname = endpoint ? endpoint : 'api.kennasecurity.com';

        request.post({url:`https://${hostname}/connectors/${connector_id}/data_file`, formData: formData, headers: {'X-Risk-Token': apikey}}, function(err, response) {
            if (err) return callback(err);

            if (!response || !response.body) {
                return callback(`Invalid response from Kenna ${JSON.stringify(response)}`);
            }


            callback(null, response);
        });
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
    if (typeof settings.num_new_risks !== 'number') return callback('Settings num_new_risks is not a valid number');

    let filteredTests = settings.raw_results.filter(raw_result => {
        return raw_result.results.some(result => {
            return result.status === 2;
        });
    });

    let vulns = [];
    let vulns_def = [];
    async.each(filteredTests, function(test, rCb) {
        let resultDetails = test.results.filter(result => {return result.status === 2 && result.resource;});

        if (!resultDetails.length) resultDetails = ['No Resource identifiers found for this test'];
        else resultDetails = resultDetails.map(result => {return result.resource;});
        let sev;
        if (test.severity === 'low'){
            sev = 2;
        } else if (test.severity === 'medium') {
            sev = 6;
        } else if (test.severity === 'high') {
            sev = 8;
        } else if (test.severity === 'critical') {
            sev = 10;
        } else {
            sev = 0;
        }
        let localVuln = {
            'scanner_identifier': test.id,
            'scanner_type': 'Aqua CSPM',
            'scanner_score': sev,
            'last_seen_at': settings.timestamp,
            'status': 'open',
            'details': JSON.stringify(resultDetails)
        };

        let localVulnDef = {
            'scanner_identifier': test.id,
            'scanner_type': 'Aqua CSPM',
            'name': test.title,
            'description': test.description,
            'solution': test.recommended_action
        };

        vulns.push(localVuln);
        vulns_def.push(localVulnDef);

        rCb();
    }, function() {
        let kennaKDI = {
            'skip_autoclose': false,
            'reset_tags': false,
            'assets': [
                {
                    'hostname': settings.account_name,
                    'tags': [`${settings.cloud}_AQUA`, `${settings.account_name}_AQUA`, `${settings.group_name}_AQUA`, (settings.account_number ? settings.account_number : '')],
                    'vulns': vulns
                }
            ],
            'vuln_defs': vulns_def
        };


        async.each(settings.endpoints, function(endpoint, cb){
            let endpointArr = endpoint.split(':::');

            raw(endpointArr[0], endpointArr[1], endpointArr[2] === 'null' ? null : endpointArr[2], kennaKDI, function(err){
                cb(err);
            });
        }, function(err){
            callback(err);
        });
    });


};


module.exports = {
    raw: raw,
    result: result
};