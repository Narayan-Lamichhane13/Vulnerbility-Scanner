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
        self.headers = {
            'User-Agent': 'VulnerabilityScanner'
        }
        # Rate limiting and caching setup for efficient API usage
        self.last_request_time = 0
        self.request_delay = 6    # Limit to 10 requests per minute
        self.max_retries = 3      # Number of retry attempts on failed requests
        self.cache = {}           # Store previous lookups to reduce API calls

    def search_cve(self, product, version):
        cve_list = []
        if not product or not version:
            return cve_list

        key = (product.lower(), version.lower())
        if key in self.cache:
            return self.cache[key]  # Return cached results if available

        params = {
            'keywordSearch': f"{product} {version}",
            'resultsPerPage': '5',
            'apiKey': self.api_key  # Include API key as a query parameter
        }

        try:
            if not self.api_key:
                logging.error("NVD API key not found. Please set the NVD_API_KEY environment variable.")
                return cve_list

            # Implement rate limiting to prevent API throttling
            elapsed_time = time.time() - self.last_request_time
            if elapsed_time < self.request_delay:
                time.sleep(self.request_delay - elapsed_time)

            # Retry logic with exponential backoff
            retries = 0
            while retries <= self.max_retries:
                try:
                    response = requests.get(self.api_url, headers=self.headers, params=params)
                    if response.status_code == 200:
                        break
                    elif response.status_code in [429, 503]:
                        retries += 1
                        wait_time = 2 ** retries
                        logging.warning(f"API rate limit reached. Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                    else:
                        response.raise_for_status()
                except requests.exceptions.RequestException as e:
                    if retries < self.max_retries:
                        retries += 1
                        wait_time = 2 ** retries
                        logging.warning(f"Request failed. Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                    else:
                        logging.error(f"Error fetching CVE data: {str(e)}")
                        return cve_list
            else:
                logging.error("Maximum retries reached. Unable to fetch CVE data.")
                return cve_list
            self.last_request_time = time.time()
            data = response.json()
            
            # Parse and extract relevant vulnerability information
            if 'vulnerabilities' in data:
                for vuln in data['vulnerabilities']:
                    cve = vuln.get('cve', {})
                    # Extract CVE ID, description, and severity score
                    cve_list.append({
                        'id': cve.get('id'),
                        'description': cve.get('descriptions', [{}])[0].get('value', ''),
                        'severity': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A')
                    })
            
            # Cache results to improve performance on repeated lookups
            self.cache[key] = cve_list
            return cve_list

        except requests.exceptions.RequestException as e:
            # Log API errors and return empty list instead of failing
            logging.error(f"Error fetching CVE data: {str(e)}")
            return cve_list