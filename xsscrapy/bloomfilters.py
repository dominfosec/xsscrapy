from pybloom import BloomFilter
from scrapy.utils.job import job_dir
from scrapy.dupefilters import BaseDupeFilter
from .settings import bloomfilterSize

class BloomURLDupeFilter(BaseDupeFilter):
    """Request Fingerprint duplicates filter"""

    def __init__(self, path=None):
        self.file = None
        self.fingerprints = BloomFilter(bloomfilterSize*10, 0.0001)

    @classmethod
    def from_settings(cls, settings):
        return cls(job_dir(settings))

    def request_seen(self, request):
        fp = request.url
        if fp in self.fingerprints:
            return True
        self.fingerprints.add(fp)

    def close(self, reason):
        self.fingerprints = None

    def request_seen(self, request):
        parsed_url = urlparse(request.url)
        path = parsed_url.path
        query = parsed_url.query
        params = parse_qsl(query)

        # Create a unique key for each path-parameter combination
        unique_keys = [f"{path}?{param}={value}" for param, value in params]

        for key in unique_keys:
            if key in self.fingerprints:
                return True  # Duplicate found
            self.fingerprints.add(key)
        return False  # Not a duplicate
