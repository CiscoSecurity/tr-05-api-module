from ctrlibrary.core import client, settings


def ctr_post_data(payload, section_url, target_url, **kwargs):
    """Send POST request to Threat Response server

    :param payload: Data that is sent to the server (e.g. {'type': 'sha256'})
    :param section_url: Specify url for type of the operation (e.g.
        '/iroh/iroh-inspect' or '/iroh/iroh-enrich')
    :param target_url: Specify url for target of the operation (e.g.
        '/deliberate/observables' or '/refer/observables')
    :return: Response from the server

    """
    return client.post(
        ''.join((settings.server.ctr_hostname, section_url, target_url)),
        json=payload,
        **kwargs
    )


def ctr_get_data(section_url, target_url, **kwargs):
    """Send GET request to Threat Response server

    :param section_url: Specify url for type of the operation (e.g.
        '/iroh/iroh-inspect' or '/iroh/iroh-enrich')
    :param target_url: Specify url for target of the operation (e.g.
        '/deliberate/observables' or '/refer/observables')
    :return: Response from the server

    """
    return client.get(
        ''.join((settings.server.ctr_hostname, section_url, target_url)),
        **kwargs
    )
