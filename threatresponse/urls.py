from .exceptions import InvalidRegionError


_url_patterns_by_api_family = {
    'visibility': 'https://visibility{region}.amp.cisco.com',
    'private_intel': 'http://private.intel{region}amp.cisco.com',
}


def _url_for_region(url_pattern, region):
    return url_pattern.format(region='.' + region if region != '' else '')


_urls_by_region = {
    region: {
        api_family: _url_for_region(url_pattern, region)
        for api_family, url_pattern in _url_patterns_by_api_family.items()
    }
    for region in (
        '',
        'eu',
        'apjc',
    )
}


def urls_for_region(region=None):
    if region is None:
        region = ''

    if region not in _urls_by_region:
        # Use `repr` to make each region enclosed in quotes.
        raise InvalidRegionError(
            'Invalid region {}, must be one of: {}.'.format(
                repr(region),
                ', '.join(map(repr, _urls_by_region.keys())),
            )
        )

    return _urls_by_region[region]
