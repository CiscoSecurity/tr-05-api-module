from six.moves.urllib.parse import quote

from .exceptions import RegionError


_url_patterns_by_api_family = {
    'visibility': 'https://visibility{region}.amp.cisco.com',
    'private_intel': 'https://private.intel{region}.amp.cisco.com',
    'global_intel': 'https://intel{region}.amp.cisco.com',
}


_urls_by_region = {
    '': {
        'visibility':
            _url_patterns_by_api_family['visibility'].format(region=''),
        'private_intel':
            _url_patterns_by_api_family['private_intel'].format(region=''),
        'global_intel':
            _url_patterns_by_api_family['global_intel'].format(region='')
    },
    'eu': {
        'visibility':
            _url_patterns_by_api_family['visibility'].format(region='eu'),
        'private_intel':
            _url_patterns_by_api_family['private_intel'].format(region='eu'),
        'global_intel':
            _url_patterns_by_api_family['global_intel'].format(region='eu')
    },
    'apjc': {
        'visibility':
            _url_patterns_by_api_family['visibility'].format(region='apjc'),
        'private_intel':
            _url_patterns_by_api_family['private_intel'].format(region='apjc'),
        'global_intel':
            _url_patterns_by_api_family['global_intel'].format(region='apjc')
    }
}


def url_for(region, family):
    if region is None:
        region = ''

    if region not in _urls_by_region:
        # Use `repr` to make each region enclosed in quotes.
        raise RegionError(
            'Invalid region {}, must be one of: {}.'.format(
                repr(region),
                ', '.join(map(repr, _urls_by_region.keys())),
            )
        )

    return _urls_by_region[region][family]


def join(base, *parts):
    return base.rstrip('/') + '/' + '/'.join(
        quote(str(part).strip('/'), safe='')
        for part in parts
    )
