from six.moves.urllib.parse import quote

from .exceptions import RegionError

_url_patterns_by_api_family = {
    'visibility': 'https://visibility{region}.amp.cisco.com',
    'private_intel': 'https://private.intel{region}.amp.cisco.com',
    'global_intel': 'https://intel{region}.amp.cisco.com'
}


def _url_for_region(url_pattern, region):
    # Fall back to the default region.
    if region == 'us':
        region = ''

    return url_pattern.format(region='.' + region if region != '' else '')


def _urls_by_region(urls):
    return dict(
        (
            region,
            dict(
                (api_family, _url_for_region(url_pattern, region))
                for api_family, url_pattern in urls.items()
            )
        )
        for region in (
            '',
            'us',
            'eu',
            'apjc',
        )
    )


def url_for(region, family, environment=None):
    # Fall back to the default region.
    if region is None:
        region = ''
    # Fall back to the default environment.
    if environment is None:
        environment = _url_patterns_by_api_family
    if region not in _urls_by_region(environment):
        # Use `repr` to make each region enclosed in quotes.
        raise RegionError(
            'Invalid region {}, must be one of: {}.'.format(
                repr(region),
                ', '.join(map(repr, _urls_by_region(environment).keys())),
            )
        )

    return _urls_by_region(environment)[region][family]


def join(base, *parts):
    return base.rstrip('/') + '/' + '/'.join(
        quote(str(part).strip('/'), safe='')
        for part in parts
    )
