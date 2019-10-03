[![Gitter chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Response "Gitter chat")
[![Travis build](https://travis-ci.com/CiscoSecurity/tr-05-api-module.svg)](https://travis-ci.com/CiscoSecurity/tr-05-api-module)

### Threat Response Python API Module:

Python API Module for Threat Response APIs

### Installation:

* Local:

```bash
python setup.py install
pip show threatresponse
```

* GitHub:

```bash
pip install git+https://github.com/CiscoSecurity/tr-05-api-module.git[@branch_name_or_release_version]
pip show threatresponse
```

* PyPi:

```bash
pip install threatresponse[==release_version]
pip show threatresponse
```

### Usage:

```python
from threatresponse import ThreatResponse

tr = TreatResponse(
    client_id='<YOUR TR CLIENT ID>',  # required
    client_password='<YOUR TR CLIENT PASSWORD>',  # required
    region='<YOUR TR REGION>',  # optional
    logger=<SOME LOGGER INSTANCE>,  # optional
    proxy='<SOME PROXY URL>',  # optional
)
```

- `client_id` and `client_password` credentials must be taken from an existing
API client for accessing the Cisco Threat Response APIs.
The official documentation on how to create such a client can be found
[here](https://visibility.amp.cisco.com/#/help/integration).
Make sure to properly set some scopes which will grant the client
different (ideally minimum) privileges.
- `region` must be one of: `''` (default), `'eu'`, `'apjc'`.
Other regions are not supported yet.
- `logger` must be an (already configured) instance of the built-in
`logging.Logger` class (or one of its descendants).
- `proxy` must be a URL in the format: `http[s]://[username[:password]@]host[:port]`.
