from .assertions import *

from threatresponse.api.response import ResponseAPI


def test_respond_observables_succeeds():
    request = invoke(lambda api: api.respond.observables(payload), ResponseAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-response/respond/observables',
        json=payload)


def test_respond_trigger_succeeds():
    request = invoke(lambda api: api.respond.trigger('Monty Python!',
        'x|y&z',
        'spam',
        'eggs',
        x=1, y=2, z=3,), ResponseAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-response/respond/trigger/Monty%20Python%21/x%7Cy%26z',
        params={'x': 1, 'y': 2, 'z': 3,
                'observable_type': 'spam',
                'observable_value': 'eggs'},
    )


def test_respond_trigger_fails():
    request = invoke_with_failure(lambda api: api.respond.trigger('Monty Python!',
        'x|y&z',
        'spam',
        'eggs',
        x=1, y=2, z=3,), ResponseAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-response/respond/trigger/Monty%20Python%21/x%7Cy%26z',
        params={'x': 1, 'y': 2, 'z': 3,
                'observable_type': 'spam',
                'observable_value': 'eggs'},
    )

def test_respond_observables_fails():
    request = invoke_with_failure(lambda api: api.respond.observables(payload), ResponseAPI)
    request.post.assert_called_once_with(
                '/iroh/iroh-response/respond/observables',
                json=payload)
