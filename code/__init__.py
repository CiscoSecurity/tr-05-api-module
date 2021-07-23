# Make the main class importable from the root package directly.
from api.threatresponse.client import ThreatResponse

# Load the current version meta-attribute into the package.
from api.threatresponse.version import __version__
