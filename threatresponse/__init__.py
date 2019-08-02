# Make the main class importable from the root package directly.
from .client import ThreatResponse

# Load the current version meta-attribute into the package.
from .version import __version__
