import mock as mock
from requests.exceptions import HTTPError

from tests.base_test import BaseTestCase
from threatresponse.api.observe import ObserveAPI


class ObservableTestCase(BaseTestCase):

    def test_observables(self):

        payload = [{'type': 'sha256', 'value': '01f30887a828344f6cf574bb05bd0bf571fc35979a3032377b95fb0d692b8061'}]

        response_mock = mock.MagicMock()
        response_mock.json.return_value = {'foo': 'bar'}

        request_mock = mock.MagicMock()
        request_mock.post.return_value = response_mock

        result = ObserveAPI(request_mock).observables(payload)

        self.assertEqual(result, response_mock.json())

        request_mock.post.assert_called_once_with(
            'https://visibility.amp.cisco.com/iroh/iroh-enrich/observe/observables',
            json=payload
        )

    def test_observables_error(self):

        payload = [{'type': 'sha256', 'value': '01f30887a828344f6cf574bb05bd0bf571fc35979a3032377b95fb0d692b8061'}]

        response_mock = mock.MagicMock()
        response_mock.json.return_value = {'foo': 'bar'}

        request_mock = mock.MagicMock()

        def raise_for_status():
            raise HTTPError(
                'Mocked error message',
                request=request_mock,
                response=response_mock,
            )

        response_mock.raise_for_status.side_effect = raise_for_status
        request_mock.post.return_value = response_mock

        with self.assertRaises(HTTPError):
            ObserveAPI(request_mock).observables(payload)

        request_mock.post.assert_called_once_with(
            'https://visibility.amp.cisco.com/iroh/iroh-enrich/observe/observables',
            json=payload
        )


class SightingTestCase(BaseTestCase):

    def test_observables(self):
        # TODO:
        payload = [{'type': 'sha256', 'value': '01f30887a828344f6cf574bb05bd0bf571fc35979a3032377b95fb0d692b8061'}]

        response_mock = mock.MagicMock()
        response_mock.json.return_value = {'foo': 'bar'}

        request_mock = mock.MagicMock()
        request_mock.post.return_value = response_mock

        result = ObserveAPI(request_mock).sighting(payload)

        self.assertEqual(result, response_mock.json())

        request_mock.post.assert_called_once_with(
            'https://visibility.amp.cisco.com/iroh/iroh-enrich/observe/sighting',
            json=payload
        )

    def test_observables_error(self):
        payload = [{'type': 'sha256', 'value': '01f30887a828344f6cf574bb05bd0bf571fc35979a3032377b95fb0d692b8061'}]

        response_mock = mock.MagicMock()
        response_mock.json.return_value = {'404': 'bar'}

        request_mock = mock.MagicMock()

        def raise_for_status():
            raise HTTPError(
                'Mocked error message',
                request=request_mock,
                response=response_mock,
            )

        response_mock.raise_for_status.side_effect = raise_for_status
        request_mock.post.return_value = response_mock

        with self.assertRaises(HTTPError):
            ObserveAPI(request_mock).sighting(payload)

        request_mock.post.assert_called_once_with(
            'https://visibility.amp.cisco.com/iroh/iroh-enrich/observe/sighting',
            json=payload
        )


class SightingRefTestCase(BaseTestCase):

    def test_observables(self):
        # ToDO:
        payload = [{'type': 'sha256', 'value': '01f30887a828344f6cf574bb05bd0bf571fc35979a3032377b95fb0d692b8061'}]

        response_mock = mock.MagicMock()
        response_mock.json.return_value = {'foo': 'bar'}

        request_mock = mock.MagicMock()
        request_mock.post.return_value = response_mock

        result = ObserveAPI(request_mock).sighting_ref(payload)

        self.assertEqual(result, response_mock.json())

        request_mock.post.assert_called_once_with(
            'https://visibility.amp.cisco.com/iroh/iroh-enrich/observe/sighting_ref',
            json=payload
        )

    def test_observables_error(self):
        payload = [{'type': 'sha256', 'value': '01f30887a828344f6cf574bb05bd0bf571fc35979a3032377b95fb0d692b8061'}]

        response_mock = mock.MagicMock()
        response_mock.json.return_value = {'404': 'bar'}

        request_mock = mock.MagicMock()

        def raise_for_status():
            raise HTTPError(
                'Mocked error message',
                request=request_mock,
                response=response_mock,
            )

        response_mock.raise_for_status.side_effect = raise_for_status
        request_mock.post.return_value = response_mock

        with self.assertRaises(HTTPError):
            ObserveAPI(request_mock).sighting_ref(payload)

        request_mock.post.assert_called_once_with(
            'https://visibility.amp.cisco.com/iroh/iroh-enrich/observe/sighting_ref',
            json=payload
        )