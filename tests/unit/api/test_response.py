from threatresponse.api.response import ResponseAPI

from .assertions import *


def test_respond_observables_succeeds():
    request = invoke(ResponseAPI, lambda api: api.respond.observables(payload))
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-response/respond/observables',
        json=payload
    )


def test_respond_trigger_succeeds():
    params = {'x': 1, 'y': 2, 'z': 3}

    request = invoke(
        ResponseAPI,
        lambda api: api.respond.trigger(
            'Monty Python!',
            'x|y&z',
            'spam',
            'eggs',
            params=params
        )
    )

    params.update({
        'observable_type': 'spam',
        'observable_value': 'eggs'
    })

    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-response/respond/trigger/Monty%20Python%21/x%7Cy%26z',
        params=params
    )


def test_respond_trigger_fails():
    params = {'x': 1, 'y': 2, 'z': 3}

    request = invoke_with_failure(
        ResponseAPI,
        lambda api: api.respond.trigger(
            'Monty Python!',
            'x|y&z',
            'spam',
            'eggs',
            params=params
        )
    )

    params.update({
        'observable_type': 'spam',
        'observable_value': 'eggs'
    })

    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-response/respond/trigger/Monty%20Python%21/x%7Cy%26z',
        params=params,
    )


def test_respond_observables_fails():
    request = invoke_with_failure(
        ResponseAPI,
        lambda api: api.respond.observables(payload)
    )

    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-response/respond/observables',
        json=payload
    )
