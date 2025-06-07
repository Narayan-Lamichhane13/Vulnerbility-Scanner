import requests
import logging
import os
import time

# CVELookup class handles the interaction with the NVD (National Vulnerability Database) API
# to search for known vulnerabilities of software products and versions
class CVELookup:
    def __init__(self):
        # NVD API v2.0 endpoint
        self.api_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        # Get API key from environment variables for secure access
        self.api_key = os.getenv('NVD_API_KEY')
        # Identify our scanner to the API service
        self.headers = {'User-Agent': 'VulnerabilityScanner'}
        # Rate limiting and caching setup for efficient API usage
        self.last_request_time = 0
        self.request_delay = 6    # Limit to 10 requests per minute
        self.max_retries = 3      # Number of retry attempts on failed requests
        self.cache = {}           # Store previous lookups to reduce API calls

    def search_cve(self, product, version):
        if not product or not version or not self.api_key:
            return []

        key = (product.lower(), version.lower())
        if key in self.cache:
            return self.cache[key]  # Return cached results if available

        params = {
            'keywordSearch': f"{product} {version}",
            'resultsPerPage': '5',
            'apiKey': self.api_key  # Include API key as a query parameter
        }

        # Implement rate limiting to prevent API throttling
        elapsed = time.time() - self.last_request_time
        if elapsed < self.request_delay:
            time.sleep(self.request_delay - elapsed)

        # Retry logic with exponential backoff
        retries = 0
        while retries <= self.max_retries:
            try:
                resp = requests.get(self.api_url, headers=self.headers, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    break
                elif resp.status_code in (429, 503):
                    retries += 1
                    time.sleep(2 ** retries)
                else:
                    resp.raise_for_status()
            except requests.RequestException as e:
                if retries < self.max_retries:
                    retries += 1
                    time.sleep(2 ** retries)
                else:
                    logging.error(f"CVE lookup failed: {e}")
                    return []
        else:
            logging.error("Max CVE retries reached")
            return []

        self.last_request_time = time.time()
        
        # Parse and extract relevant vulnerability information
        vulns = []
        for item in data.get('vulnerabilities', []):
            c = item.get('cve', {})
            vulns.append({
                'id': c.get('id', 'N/A'),
                'description': c.get('descriptions', [{}])[0].get('value', ''),
                'severity': c.get('metrics', {}).get('cvssMetricV31', [{}])[0]
                              .get('cvssData', {}).get('baseScore', 'N/A')
            })
        
        # Cache results to improve performance on repeated lookups
        self.cache[key] = vulns
        return vulns