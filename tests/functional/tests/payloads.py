from ctrlibrary.core.datafactory import gen_ip

SERVER_VERSION = '1.1.3'
observable = {'type': 'ip', 'value': gen_ip()}

ACTOR_PAYLOAD = {
    'actor_type': 'Hacker',
    'description': 'For Test',
    'confidence': 'High',
    'schema_version': SERVER_VERSION,
    'source': 'Test source',
    'type': 'actor',
    'short_description': 'test',
    'title': 'for test',
    'external_ids': ['3']
}

PUT_ACTOR_PAYLOAD = {
    'source': 'new source point',
    'actor_type': 'Hacker',
    'description': 'for Test',
    'confidence': 'High',
    'schema_version': SERVER_VERSION,
    'type': 'actor',
    'short_description': 'test',
    'title': 'for test'
}

ASSET_PAYLOAD = {
    'asset_type': 'data',
    'description': 'For Test',
    'valid_time': {
        "start_time": "2021-07-27T07:55:38.193Z",
        "end_time": "2021-07-27T07:55:38.193Z"},
    'schema_version': SERVER_VERSION,
    'source': 'test source',
    'type': 'asset',
    'short_description': 'test',
    'title': 'for test',
    'external_ids': ['3']
}

PUT_ASSET_PAYLOAD = {
    'source': 'new source point',
    'asset_type': 'device',
    'description': 'for Test',
    'valid_time': {
        "start_time": "2021-07-27T07:55:38.193Z",
        "end_time": "2021-07-27T07:55:38.193Z"},
    'schema_version': SERVER_VERSION,
    'type': 'asset',
    'short_description': 'test',
    'title': 'for test',
    'external_ids': ['3']
}

ATTACK_PATTERN_PAYLOAD = {
    'description': (
        'A boot kit is a malware variant that modifies the boot sectors of'
        ' a hard drive'
    ),
    'schema_version': SERVER_VERSION,
    'type': 'attack-pattern',
    'short_description': 'desc for test',
    'source': 'new source point',
    'title': 'for test',
    'external_ids': ['3']
}

PUT_ATTACK_PATTERN_PAYLOAD = {
    'short_description': 'Updated descr',
    'description': (
        'A standalone malware that replicates itself in order to'
        ' spread to other computers'
    ),
    'title': 'for test'
}

CAMPAIGN_PAYLOAD = {
    'campaign_type': 'Critical',
    'confidence': 'Medium',
    'type': 'campaign',
    'schema_version': SERVER_VERSION,
    'description': 'For test',
    'short_description': 'Short test description',
    'title': 'Test'
}

PUT_CAMPAIGN_PAYLOAD = {
    'title': 'New demo campaign',
    'campaign_type': 'Critical',
    'description': 'For Test',
    'short_description': 'Short test description'
}

COA_PAYLOAD = {
    'description': 'COA entity we use for bulk testing',
    'coa_type': 'Diplomatic Actions',
    'type': 'coa',
    'schema_version': SERVER_VERSION,
    'short_description': 'Short test description',
    'title': 'Test',
    'external_ids': ['3']
}

INCIDENT_PAYLOAD = {
    'confidence': 'Low',
    'incident_time': {
        'opened': "2014-01-11T00:40:48.212Z"
    },
    'status': 'New',
    'type': 'incident',
    'schema_version': SERVER_VERSION,
    'external_ids': ['3']
}

PUT_INCIDENT_PAYLOAD = {
    'confidence': 'Medium',
    'incident_time': {
        'opened': "2016-02-11T00:40:48.212Z"
    },
    'status': 'Open',
}

INDICATOR_PAYLOAD = {
    'producer': 'producer',
    'schema_version': SERVER_VERSION,
    'type': 'indicator',
    'revision': 0,
    'external_ids': ['3']
}

CASEBOOK_PAYLOAD = {
    'type': 'casebook',
    'title': 'Case September 24, 2019 2:34 PM',
    'short_description': 'New Casebook',
    'description': 'New Casebook for malicious tickets',
    'observables': [observable],
    'timestamp': '2019-09-24T11:34:18.000Z',
    'external_ids': ['3']
}

CASEBOOK_PATCH_PAYLOAD = {
    'type': 'casebook',
    'title': 'Case November, 2021 0:00 PM',
    'short_description': 'Patched Casebook',
    'description': 'Patched entity',
    'observables': [],
    'timestamp': '2019-09-24T11:34:18.000Z'
}

DATA_TABLE_PAYLOAD = {
    'schema_version': SERVER_VERSION,
    'type': 'data-table',
    'columns': [{'name': 'column', 'type': 'string'}],
    'rows': [[{}]]
}

JUDGEMENT_PAYLOAD = {
    'confidence': 'High',
    'disposition': 2,
    'disposition_name': 'Malicious',
    'observable': observable,
    'priority': 99,
    'schema_version': SERVER_VERSION,
    'severity': 'Medium',
    'source': 'source',
    'type': 'judgement',
    'external_ids': ['3']
}

PUT_JUDGEMENT_PAYLOAD = {
    'confidence': 'High',
    'priority': 43,
    'severity': 'High',
    'observable': observable,
    'source': 'source',
}

IDENTITY_ASSERTION_PAYLOAD = {
    'identity': {
        'observables': [
            {
                'type': 'ip',
                'value': '10.0.0.1'
            },
        ]
    },
    'schema_version': SERVER_VERSION,
    'type': 'identity-assertion',
    'source': 'ATQC data',
    'assertions': [
        {
            'name': 'severity',
            'value': 'Medium'
        }
    ],
}

PUT_IDENTITY_ASSERTION_PAYLOAD = {
    'identity': {
        'observables': [
            {
                'type': 'ip',
                'value': '10.0.0.1'
            },
        ]
    },
    'assertions': [
        {
            'name': 'severity',
            'value': 'Low'
        }
    ],
}

SIGHTING_PAYLOAD = {
    'count': 1,
    'observed_time': {
        'start_time': '2019-09-25T00:40:48.212Z',
        'end_time': '2019-09-25T00:40:48.212Z'
    },
    'confidence': 'High',
    'type': 'sighting',
    'schema_version': SERVER_VERSION,
    'external_ids': ['3'],
    'observables': [observable]
}

PUT_SIGHTING_PAYLOAD = {
    'confidence': 'Low',
    'observed_time': {
        'start_time': '2019-09-25T00:40:48.212Z',
        'end_time': '2019-09-25T00:40:48.212Z'
    },
}

INVESTIGATION_PAYLOAD = {
    'title': 'Demo investigation',
    'description': 'Request investigation for yesterday malware',
    'type': 'investigation',
    'source': 'a source',
    'schema_version': SERVER_VERSION,
    'external_ids': ['3']
}

MALWARE_PAYLOAD = {
    'type': 'malware',
    'schema_version': SERVER_VERSION,
    'labels': ['malware'],
    'description': 'Test description',
    'title': 'Title for test',
    'short_description': 'Short test description',
    'external_ids': ['3']

}

PUT_MALWARE_PAYLOAD = {'labels': ['malware'],
                       'description': 'Test description',
                       'title': 'Changed title for test',
                       'short_description': 'Short test description'
                       }

TARGET_RECORD_PAYLOAD = {
    "targets": [
        {
            "type": "string",
            "observables": [observable],
            "observed_time": {
                "start_time": "2021-08-05T14:17:54.726Z",
                "end_time": "2021-08-05T14:17:54.726Z"
            }
        }
    ],
    'source': 'For test',
    'type': 'target-record',
    'schema_version': SERVER_VERSION,
    'external_ids': ['3']
}

PUT_TARGET_RECORD_PAYLOAD = {
    'source': 'Updated source',
    'targets': [
        {
            "type": "string",
            "observables": [
                {
                    "value": "asdf.com",
                    "type": "domain"
                }
            ],
            "observed_time": {
                "start_time": "2021-08-05T14:17:54.726Z",
                "end_time": "2021-08-05T14:17:54.726Z"
            }
        }
    ]
}

TOOL_PAYLOAD = {
    'labels': ['tool'],
    'type': 'tool',
    'schema_version': SERVER_VERSION,
    'description': 'Test description',
    'title': 'Title for test',
    'short_description': 'Short test description',
    'external_ids': ['3']
}

PUT_TOOL_PAYLOAD = {'labels': ['tool'],
                    'description': 'Test description',
                    'title': 'Changed title for test',
                    'short_description': 'Short test description'
                    }

VULNERABILITY_PAYLOAD = {
    'description': 'Browser vulnerability',
    'type': 'vulnerability',
    'schema_version': SERVER_VERSION,
    'external_ids': ['3']
}

WEAKNESS_PAYLOAD = {
    'description': (
        'The software receives input from an upstream component, but it'
        ' does not neutralize or incorrectly neutralizes code syntax'
        ' before using the input in a dynamic evaluation call'
        ' (e.g. \"eval\").'),
    'schema_version': SERVER_VERSION,
    'likelihood': 'Medium',
    'type': 'weakness',
    'external_ids': ['3']
}

RELATIONSHIP_PAYLOAD = {
    'description': 'Test relation',
    'schema_version': SERVER_VERSION,
    'type': 'relationship',
    'relationship_type': 'indicates',
    'external_ids': ['3']
}

ASSET_MAPPING_PAYLOAD = {
    'asset_type': 'data',
    'confidence': 'High',
    'stability': 'Physical',
    'specificity': 'Medium',
    'valid_time': {
        "start_time": "2021-07-27T07:55:38.193Z",
        "end_time": "2021-07-27T07:55:38.193Z"},
    'schema_version': SERVER_VERSION,
    'observable': {
        'value': '1.1.1.1',
        'type': 'ip'
    },
    'source': 'test source',
    'type': 'asset-mapping',
    'external_ids': ['3']
}

ASSET_PROPERTIES_PAYLOAD = {
    'valid_time': {
        "start_time": "2021-07-27T07:55:38.193Z",
        "end_time": "2021-07-27T07:55:38.193Z"},
    'schema_version': SERVER_VERSION,
    'source': 'test source',
    'type': 'asset-properties',
    'external_ids': ['3']
}

BUNDLE_PAYLOAD = {
    "operation": "add",
    "bundle": {
        "description": "string",
        "valid_time": {
            "start_time": "2021-08-26T11:48:51.490Z",
            "end_time": "2021-08-26T11:48:51.490Z"
        },
        "schema_version": "1.1.3",
        "type": "bundle",
        "source": "Source For bundle",
        "short_description": "Bundle description",
        "title": "Title for test"
    }
}

FEED_PAYLOAD = {
    "schema_version": SERVER_VERSION,
    "revision": 0,
    "type": "feed",
    "output": "observables",
    "feed_type": "indicator",
}

FEEDBACK_PAYLOAD = {
    'schema_version': SERVER_VERSION,
    'type': 'feedback',
    'feedback': 1,
    'reason': 'improvement'
}
