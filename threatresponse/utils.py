import json

import requests


def raise_for_status(response):
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as error:
        # Try to extend the default error message with the response payload
        # in order to give the user more insight about what went wrong
        try:
            payload = response.json()
        except json.JSONDecodeError:
            pass
        else:
            message = error.args[0]  # 1-element tuple
            message += '\n' + json.dumps(payload, indent=4)
            error.args = (message,)
        raise error
