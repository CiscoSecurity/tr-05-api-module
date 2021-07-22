from api.threatresponse.request.proxied import ProxiedRequest


def test_that_proxied_request_properly_configures_session_proxies():
    proxy = 'proxy://111.222.333.444:5555'
    request = ProxiedRequest(proxy=proxy)

    assert request._proxy == proxy
    assert request._session.proxies == {'http': proxy, 'https': proxy}
