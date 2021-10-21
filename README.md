[![Gitter Chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Response "Gitter Chat")
[![Travis CI Build Status](https://travis-ci.com/CiscoSecurity/tr-05-api-module.svg?branch=develop)](https://travis-ci.com/CiscoSecurity/tr-05-api-module)
[![PyPi Version](https://img.shields.io/pypi/v/threatresponse.svg)](https://pypi.python.org/pypi/threatresponse)
[![Python Versions](https://img.shields.io/pypi/pyversions/threatresponse.svg)](https://pypi.python.org/pypi/threatresponse)

# Threat Response API Module

Python API Module for Threat Response APIs.

## Installation

* Local

```bash
pip install --upgrade .
pip show threatresponse
```

* GitHub

```bash
pip install --upgrade git+https://github.com/CiscoSecurity/tr-05-api-module.git[@branch_name_or_release_version]
pip show threatresponse
```

* PyPi

```bash
pip install --upgrade threatresponse[==release_version]
pip show threatresponse
```

## Usage

```python
from threatresponse import ThreatResponse

client = ThreatResponse(
    client_id='<YOUR TR CLIENT ID>',  # required
    client_password='<YOUR TR CLIENT PASSWORD>',  # required
    region='<YOUR TR REGION>',  # optional
    logger=<SOME LOGGER INSTANCE>,  # optional
    proxy='<SOME PROXY URL>',  # optional
    environment='<SPECIFIC ENVIRONMENT>' # optional
)
```

- `client_id` and `client_password` credentials must be taken from an existing
API client for accessing the Cisco Threat Response APIs.
The official documentation on how to create such a client can be found
[here](https://visibility.amp.cisco.com/#/help/integration).
Make sure to properly set some scopes which will grant the client
different (ideally minimum) privileges.
- `region` must be one of: `''` or `'us'` (default), `'eu'`, `'apjc'`.
Other regions are not supported yet.
- `logger` must be an (already configured) instance of the built-in
`logging.Logger` class (or one of its descendants).
- `timeout` must be a number (`int` or `float`) meaning the default amount of
time (in seconds) to wait for the server to send data before giving up and
raising an exception. Can be overwritten by explicitly specifying `timeout` on
each call to any endpoint.
- `proxy` must be a URL in the format: `http[s]://[username[:password]@]host[:port]`.
- `environment` must be a dict in the format:
    {
        'visibility': 'https://www.example.com',
        'private_intel': 'https://www.example.come',
        'global_intel': 'https://www.example.com',
    }
By default will be used: 
    {
        'visibility': 'https://visibility{region}.amp.cisco.com',
        'private_intel': 'https://private.intel{region}.amp.cisco.com',
        'global_intel': 'https://intel{region}.amp.cisco.com',
    }
  
### Concrete Usage

- Inspect

Inspect allows to find an observable in a concrete string.
```python
response = client.inspect.inspect({'content': 'example.com'})
```

- Observe

Observe returns summary for an observable.
```python
response = client.enrich.observe.observables(
    [{'type': 'sha256', 'value': '8A32950CD96C5EF88F9DCBB66A08F59A7E8D8E5FECCDE9E115FBAA46D9AF88F9'}]
)
```

- Deliberate

Deliberate returns judgments based on added modules.
```python
response = client.enrich.deliberate.observables(
    [{'type': 'sha256', 'value': '8A32950CD96C5EF88F9DCBB66A08F59A7E8D8E5FECCDE9E115FBAA46D9AF88F9'}]
)
```

### Commands

For your convenience, we have made some predefined commands that you can use.

- Verdicts

Verdicts returns verdicts from all modules if the modules are configured. Accepts multiple observables.
```python
response = client.commands.verdict(
    'string with observables ("8A32950CD96C5EF88F9DCBB66A08F59A7E8D8E5FECCDE9E115FBAA46D9AF88F9, cisco.com")'
)
```
 
- Targets

Targets returns all available targets if the modules are configured. Accepts multiple observables.
```python
response = client.commands.targets(
    'string with observables ("8A32950CD96C5EF88F9DCBB66A08F59A7E8D8E5FECCDE9E115FBAA46D9AF88F9, cisco.com")'
)
```

### Available Endpoints

Switch between `.private_intel` and `.global_intel` if necessary.

# Actor
    actor = client.private_intel.actor
Available methods:
  - actor.post()
  - actor.get()
  - actor.put()
  - actor.delete()
  - actor.external_id()
  - actor.search.get()
  - actor.search.delete()
  - actor.search.count()
  - actor.metric.histogram()
  - actor.metric.topn()
  - actor.metric.cardinality()

# Asset
    asset = client.private_intel.asset
Available methods:
  - asset.post()
  - asset.get()
  - asset.put()
  - asset.delete()
  - asset.external_id()
  - asset.search.get()
  - asset.search.delete()
  - asset.search.count()
  - asset.metric.histogram()
  - asset.metric.topn()
  - asset.metric.cardinality()

# Asset mapping
    asset_mapping = client.private_intel.asset_mapping
Available methods:
  - asset_mapping.post()
  - asset_mapping.get()
  - asset_mapping.put()
  - asset_mapping.delete()
  - asset_mapping.expire()  
  - asset_mapping.external_id()
  - asset_mapping.search.get()
  - asset_mapping.search.delete()
  - asset_mapping.search.count()
  - asset_mapping.metric.histogram()
  - asset_mapping.metric.topn()
  - asset_mapping.metric.cardinality()

# Asset properties
    asset_properties = client.private_intel.asset_properties
Available methods:
  - asset_properties.post()
  - asset_properties.get()
  - asset_properties.put()
  - asset_properties.delete()
  - asset_properties.expire()  
  - asset_properties.external_id()
  - asset_properties.search.get()
  - asset_properties.search.delete()
  - asset_properties.search.count()
  - asset_properties.metric.histogram()
  - asset_properties.metric.topn()
  - asset_properties.metric.cardinality()

# Attack Pattern
    attack_pattern = client.private_intel.attack_pattern
Available methods:
  - attack_pattern.post()
  - attack_pattern.get()
  - attack_pattern.put()
  - attack_pattern.delete()
  - attack_pattern.external_id()
  - attack_pattern.search.get()
  - attack_pattern.search.delete()
  - attack_pattern.search.count()
  - attack_pattern.metric.histogram()
  - attack_pattern.metric.topn()
  - attack_pattern.metric.cardinality()

# Bulk 
    bulk = client.private_intel.bulk
Available methods:
  - bulk.post()
  - bulk.get()

# Bundle 
    bundle = client.private_intel.bundle
Available methods:
  - bundle.export.post()
  - bundle.export.get()
  - bundle.import_.post()

# Campaign
    campaign = client.private_intel.campaign
Available methods:
  - campaign.post()
  - campaign.get()
  - campaign.put()
  - campaign.delete()
  - campaign.external_id()
  - campaign.search.get()
  - campaign.search.delete()
  - campaign.search.count()
  - campaign.metric.histogram()
  - campaign.metric.topn()
  - campaign.metric.cardinality()

# Casebook
    casebook = client.private_intel.casebook
Available methods:
  - casebook.post()
  - casebook.get()
  - casebook.put()
  - casebook.delete()
  - casebook.external_id()
  - casebook.observables()
  - casebook.texts()
  - casebook.bundle()
  - casebook.patch()
  - casebook.search.get()
  - casebook.search.delete()
  - casebook.search.count()
  - casebook.metric.histogram()
  - casebook.metric.topn()
  - casebook.metric.cardinality()

# COA
    coa = client.private_intel.coa
Available methods:
  - coa.post()
  - coa.get()
  - coa.put()
  - coa.delete()
  - coa.external_id()
  - coa.search.get()
  - coa.search.delete()
  - coa.search.count()
  - coa.metric.histogram()
  - coa.metric.topn()
  - coa.metric.cardinality()

# DataTable
    data_table = client.private_intel.data_table
Available methods:
  - data_table.post()
  - data_table.get()
  - data_table.delete()
  - data_table.external_id()
  
# Enrich
    enrich = client.enrich
Available methods:
  - enrich.health()
  - enrich.deliberate.observables()
  - enrich.observe.observables()
  - enrich.refer.observables()

# Event
    event = client.private_intel.event
Available methods:
  - event.history()
  - event.get()
  - event.delete()
  - event.search.get()
  - event.search.delete()
  - event.search.count()

# Feed
    feed = client.private_intel.feed
Available methods:
  - feed.view.txt()
  - feed.view()
  - feed.post()
  - feed.put()
  - feed.get()
  - feed.delete()
  - feed.external_id()
  - feed.search.get()
  - feed.search.delete()
  - feed.search.count()
  
# Feedback
    feedback = client.private_intel.feedback
Available methods:
  - feedback.post()
  - feedback.get()
  - feedback.delete()
  - feedback.external_id()
  - feedback.get(_id)

# GraphQL
    graph = client.private_intel.graphql
Available methods:
  - graphql.post()

# Identity Assertion
    identity_assertion = client.private_intel.identity_assertion
Available methods:
  - identity_assertion.post()
  - identity_assertion.get()
  - identity_assertion.put()
  - identity_assertion.delete()
  - identity_assertion.external_id()
  - identity_assertion.search.get()
  - identity_assertion.search.delete()
  - identity_assertion.search.count()
  - identity_assertion.metric.histogram()
  - identity_assertion.metric.topn()
  - identity_assertion.metric.cardinality()

# Incident
    incident = client.private_intel.incident
Available methods:
  - incident.post()
  - incident.get()
  - incident.put()
  - incident.delete()
  - incident.external_id()
  - incident.link()
  - incident.status()
  - incident.sightings.incidents()
  - incident.patch()
  - incident.search.get()
  - incident.search.delete()
  - incident.search.count()
  - incident.metric.histogram()
  - incident.metric.topn()
  - incident.metric.cardinality()

# Indicator
    indicator = client.private_intel.indicator
Available methods:
  - indicator.post()
  - indicator.get()
  - indicator.put()
  - indicator.delete()
  - indicator.external_id()
  - indicator.judgements.indicators()
  - indicator.sightings.indicators()
  - indicator.search.get()
  - indicator.search.delete()
  - indicator.search.count()
  - indicator.metric.histogram()
  - indicator.metric.topn()
  - indicator.metric.cardinality()
  
# Inspect
    inspect = client.inspect
Available methods:
  - inspect.inspect()

# Int
    int = client.int
Available methods:
  - int.integration.get(_id)
  - int.integration.patch(_id)
  - int.integration.delete(_id)
  - int.integration.get()
  - int.integration.post()
  - int.module_instance.get(_id)
  - int.module_instance.patch(_id)
  - int.module_instance.delete(_id)
  - int.module_instance.get()
  - int.module_instance.post()
  - int.module_type.get(_id)
  - int.module_type.patch(_id)
  - int.module_type.delete(_id)
  - int.module_type.get()
  - int.module_type.post()
 
# Investigation
    investigation = client.private_intel.investigation
Available methods:
  - investigation.post()
  - investigation.get()
  - investigation.put()
  - investigation.delete()
  - investigation.external_id()
  - investigation.search.get()
  - investigation.search.delete()
  - investigation.search.count()
  - investigation.metric.histogram()
  - investigation.metric.topn()
  - investigation.metric.cardinality()

# Judgment
    judgment = client.private_intel.judgment
Available methods:
  - judgment.post()
  - judgment.get()
  - judgment.put()
  - judgment.delete()
  - judgment.expire()
  - judgment.external_id()
  - judgment.judgments()
  - judgment.search.get()
  - judgment.search.delete()
  - judgment.search.count()
  - judgment.metric.histogram()
  - judgment.metric.topn()
  - judgment.metric.cardinality()

# Malware
    malware = client.private_intel.malware
Available methods:
  - malware.post()
  - malware.get()
  - malware.put()
  - malware.delete()
  - malware.external_id()
  - malware.search.get()
  - malware.search.delete()
  - malware.search.count()
  - malware.metric.histogram()
  - malware.metric.topn()
  - malware.metric.cardinality()

# Metrics
    metrics = client.private_intel.metrics
Available methods:
  - metrics.get()

# Profile
    profile = client.profile
Available methods:
  - profile.whoami()
  - profile.org.get()
  - profile.org.post()

# Properties
    properties = client.private_intel.properties
Available methods:
  - properties.get()

# Relationship
    relationship = client.private_intel.relationship
Available methods:
  - relationship.post()
  - relationship.get()
  - relationship.put()
  - relationship.delete()
  - relationship.external_id()
  - relationship.search.get()
  - relationship.search.delete()
  - relationship.search.count()
  - relationship.metric.histogram()
  - relationship.metric.topn()
  - relationship.metric.cardinality()
  
# Response
    response = client.response
Available methods:
  - response.respond.observables()
  - response.respond.sighting()
  - response.respond.trigger()

# Sighting
    sighting = client.private_intel.sighting
Available methods:
  - sighting.post()
  - sighting.get()
  - sighting.put()
  - sighting.delete()
  - sighting.external_id()
  - sighting.sightings()
  - sighting.search.get()
  - sighting.search.delete()
  - sighting.search.count()
  - sighting.metric.histogram()
  - sighting.metric.topn()
  - sighting.metric.cardinality()

# SSE Device
    sse_device = client.sse_device
Available methods:
- sse_device.get_all()
- sse_device.get_by_id()
- sse_device.post()
- sse_device.patch()
- sse_device.token()
- sse_device.re_token()
- sse_device.api_proxy()
- sse_device.delete()

# SSE Tenant
    sse_tenant = client.sse_tenant
Available methods:
- sse_tenant.get_token()

# Target record
    target_record = client.private_intel.target_record
Available methods:
  - target_record.post()
  - target_record.get()
  - target_record.put()
  - target_record.delete()
  - target_record.external_id()
  - target_record.search.get()
  - target_record.search.delete()
  - target_record.search.count()
  - target_record.metric.histogram()
  - target_record.metric.topn()
  - target_record.metric.cardinality()

# Status
    status = client.private_intel.status
Available methods:
  - status.get()

# Tool
    tool = client.private_intel.tool
Available methods:
  - tool.post()
  - tool.get()
  - tool.put()
  - tool.delete()
  - tool.external_id()
  - tool.search.get()
  - tool.search.delete()
  - tool.search.count()
  - tool.metric.histogram()
  - tool.metric.topn()
  - tool.metric.cardinality()

# User Management
    user_mgmt = client.user_mgmt
Available methods:
  - user_mgmt.users.get()
  - user_mgmt.users.post()
  - user_mgmt.batch.users()
  - user_mgmt.search.users()

# Verdict
    verdict = client.private_intel.verdict
Available methods:
  - verdict.get()

# Version
    version = client.private_intel.version
Available methods:
  - version.get()

# Vulnerability
    vulnerability = client.private_intel.vulnerability
Available methods:
  - vulnerability.cpe_match_strings()
  - vulnerability.post()
  - vulnerability.get()
  - vulnerability.put()
  - vulnerability.delete()
  - vulnerability.external_id()
  - vulnerability.search.get()
  - vulnerability.search.delete()
  - vulnerability.search.count()
  - vulnerability.metric.histogram()
  - vulnerability.metric.topn()
  - vulnerability.metric.cardinality()

# Weakness
    weakness = client.private_intel.weakness
Available methods:
  - weakness.post()
  - weakness.get()
  - weakness.put()
  - weakness.delete()
  - weakness.external_id()
  - weakness.search.get()
  - weakness.search.delete()
  - weakness.search.count()
  - weakness.metric.histogram()
  - weakness.metric.topn()
  - weakness.metric.cardinality()
