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
  - actor.search()

# Attack Pattern
    attack_pattern = client.private_intel.attack_pattern
Available methods:
  - attack_pattern.post()
  - attack_pattern.get()
  - attack_pattern.put()
  - attack_pattern.delete()
  - attack_pattern.external_id()
  - attack_pattern.search()

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
  - campaign.search()

# Casebook
    casebook = client.private_intel.casebook
Available methods:
  - casebook.post()
  - casebook.get()
  - casebook.put()
  - casebook.delete()
  - casebook.external_id()
  - casebook.search()
  - casebook.observables()
  - casebook.texts()
  - casebook.bundle()
  - casebook.pathc()

# COA
    coa = client.private_intel.coa
Available methods:
  - coa.post()
  - coa.get()
  - coa.put()
  - coa.delete()
  - coa.external_id()
  - coa.search()

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
  - event.search()
  - event.get()
  - event.delete()
  
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

# Incident
    incident = client.private_intel.incident
Available methods:
  - incident.post()
  - incident.get()
  - incident.put()
  - incident.delete()
  - incident.external_id()
  - incident.search()
  - incident.link()
  - incident.status()
  - incident.sightings.incidents()
  - incident.patch()

# Indicator
    indicator = client.private_intel.indicator
Available methods:
  - indicator.post()
  - indicator.get()
  - indicator.put()
  - indicator.delete()
  - indicator.external_id()
  - indicator.search()
  - indicator.judgements.indicators()
  - indicator.sightings.indicators()
  
# Inspect
    inspect = client.inspect
Available methods:
  - inspect.inspect()
 
# Investigation
    investigation = client.private_intel.investigation
Available methods:
  - investigation.post()
  - investigation.get()
  - investigation.put()
  - investigation.delete()
  - investigation.external_id()
  - investigation.search()

# Judgment
    judgment = client.private_intel.judgment
Available methods:
  - judgment.post()
  - judgment.get()
  - judgment.put()
  - judgment.delete()
  - judgment.external_id()
  - judgment.search()
  - judgment.judgments()

# Malware
    malware = client.private_intel.malware
Available methods:
  - malware.post()
  - malware.get()
  - malware.put()
  - malware.delete()
  - malware.external_id()
  - malware.search()

# Metrics
    metrics = client.private_intel.metrics
Available methods:
  - metrics.get()

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
  - relationship.search()
  
# Response
    response = client.response
Available methods:
  - response.respond.observables()
  - response.respond.trigger()

# Sighting
    sighting = client.private_intel.sighting
Available methods:
  - sighting.post()
  - sighting.get()
  - sighting.put()
  - sighting.delete()
  - sighting.external_id()
  - sighting.search()
  - sighting.sightings()

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
  - tool.search()

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
  - vulnerability.post()
  - vulnerability.get()
  - vulnerability.put()
  - vulnerability.delete()
  - vulnerability.external_id()
  - vulnerability.search()

# Weakness
    weakness = client.private_intel.weakness
Available methods:
  - weakness.post()
  - weakness.get()
  - weakness.put()
  - weakness.delete()
  - weakness.external_id()
  - weakness.search()
