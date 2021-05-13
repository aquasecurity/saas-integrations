[![CloudSploit](https://cloudsploit.com/img/logo-big-text-100.png "CloudSploit")](https://cloudsploit.com)

CloudSploit Third-Party Integrations
=================

## Background
CloudSploit integrations allow CloudSploit alerts, scan results, and event notifications to be sent to third-party monitoring, logging, and alerting platforms. This repository is designed to separate these integrations into a common format which can be used to extend the CloudSploit platform.

## Installation
Ensure that NodeJS is installed. If not, install it from [here](https://nodejs.org/download/).

```
git clone git@github.com:cloudsploit/integrations.git
```

## Adding Integrations

Each integration must follow the same format and export the same functions. They also must accept the same input parameters, which allows CloudSploit to easily add the integration to our service. To add a new integration, create a new file in this repository for the integration you are creating (e.g `splunk.js`).

Next, export the following functions (described in detail below):

1. `raw`
2. `result`
3. `alert`
4. `event`

### raw(:endpoint, payload, callback)

This function allows raw data to be sent to the integration. This is the simplest form of the integration and allows messages to be sent directly through the integration's endpoint.

* `endpoint`
    * The API endpoint, webhook, SNS topic ARN, etc. associated with the integration.
* `payload`
    * A JSON object representing that integration's payload. The object properties will be different for each integration type.
* `callback`
    * A standard Node callback function to be called once the integration has been delivered.

### result(settings, callback)

This function will be called to deliver scan report results. The `settings` object will contain the following:

* `endpoints`
    * An array of API endpoints, webhooks, SNS topic ARNs, etc. where the result reports should be sent.
* `account_name`
    * The user-friendly name for the account
* `num_pass`, `num_warn`, `num_fail`, `num_unknown`, `num_new_risks`
    * The count of each of the result types

Each integration controls the final format of the scan report. However, the existing plugins should be used as a guide. Typically, the "heading" of the report will contain the account name, while the "details" portion will contain a summary of the result counts.

Each of the endpoints should be iterated over and passed to the `raw` function with the final payload.

### alert(settings, callback)

This function will be called to deliver specific alerts which have been pre-configured by CloudSploit user. The `settings` object will contain the following:

* `endpoints`
    * An array of API endpoints, webhooks, SNS topic ARNs, etc. where the result reports should be sent.
* `account_name`
    * The user-friendly name for the account
* `test_name`
    * The user-friendly name of the test for which the alert was triggered (e.g "CloudFront HTTPS Only")
* `test_description`
    * A description of the test that was run
* `scan_id`
    * The ID of the scan containing the result. This can be used to include a link to the full report.
* `resources` (optional)
    * If provided, this will be an array of affected AWS resources, which can be included if the integration allows for additional details.
* `result`
    * Either a `1` if the test was a `WARN` or `2` if a `FAIL`

The integration should craft a clear and concise message and description that will be delivered to the endpoint. Some integrations allow more flexibility in the amount of data that can be sent. For example, an SNS topic post must be relatively short in order to fit within the character limit for SMS delivery, while OpsGenie or PagerDuty event triggers can contain many KB of additional details.

Each of the endpoints should be iterated over and passed to the `raw` function with the final payload.

### event(settings, callback)

This function will be called when CloudSploit Events triggers an alert based on a user-defined rule. For example, the root user may have logged into the account. Or, someone may have added a new security group rule. The `settings` object will contain the following:

* `endpoints`
    * An array of API endpoints, webhooks, SNS topic ARNs, etc. where the result reports should be sent.
* `account_name`
    * The user-friendly name for the account
* `event`
    * The portion of the original event which CloudSploit used to determine the event's severity. This includes the `action` (AWS API call), `region`, `caller` (AWS user), `ip_address`, and a `message` justifying the severity rating.
* `original`
    * The entire original event delivered to CloudSploit via AWS CloudWatch Events.
* `result`
    * Either a `1` if the test was a `WARN` or `2` if a `FAIL`

The integration should craft a clear and concise alert to be sent to the integration outlining the event details and why CloudSploit marked it as a security risk (warn or fail).

Each of the endpoints should be iterated over and passed to the `raw` function with the final payload.
