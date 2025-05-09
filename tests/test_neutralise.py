import unittest
import sys
import os
import time
import logging


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add the parent directory to sys.path to access the package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.neutralise_link import neutralise

# Ensure that a wide basket of links are correctly handled
valid_links = [
    "https://google.com",
    "https://theuselessweb.com/",
    "apple.com",
    "github.com",
    "brainpolo.com",
    "brainful.bot",
    "pack.page",
    "https://x.com/brainpolohouse",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://dash.cloudflare.com/3969b354d3c59137a46b96440a394c93/brainful.one",
    "https://brainful.one/@brainfulstaff/7aec82",
]

# URLs known to redirect
redirect_links = [
    "http://google.com",  # Redirects to https://google.com
    "http://github.com",  # Redirects to https://github.com
    "https://t.co/example",  # Twitter's URL shortener - add a real one if needed
]

class TestNeutralise(unittest.TestCase):

    def test_neutralise_with_tracking_params(self):
        """
        Verify that tracking parameters are properly removed.
        """
        # Test with a real valid URL that has tracking parameters
        url = "https://example.com/?param=test&sourceid=chrome&utm_source=newsletter"

        start_time = time.time()
        result = neutralise(url)
        duration = time.time() - start_time

        logger.info(f"Neutralized tracking URL in {duration:.3f} seconds: {url}")

        # The actual functions should clean the URL
        self.assertIn("https://example.com/?param=test", result)
        self.assertNotIn("sourceid=chrome", result)
        self.assertNotIn("utm_source=newsletter", result)

    def test_neutralise_success(self):
        """
        Parameterized test that verifies all valid links can be neutralised.
        """
        for link in valid_links:
            with self.subTest(link=link):
                start_time = time.time()
                result = neutralise(link)
                duration = time.time() - start_time

                logger.info(f"Neutralized URL in {duration:.3f} seconds: {link}")

                # All results should be strings (not None)
                self.assertIsNotNone(result, f"Failed to neutralise {link}")

                # If link didn't have protocol, it should be added
                if not link.startswith("http"):
                    self.assertTrue(result.lower().startswith("http"),
                                   f"Protocol not added to {link}, got {result}")

                # Convert the domain to lowercase for comparison
                original_domain = link.replace("https://", "").replace("http://", "").split("/")[0].lower()
                clean_domain = original_domain.replace("www.", "")

                # Check for domain presence regardless of redirects
                # Use less strict check - just ensure the primary domain name is in the result
                base_domain = clean_domain.split('.')[0]
                if "." in clean_domain:
                    # Handle cases where URLs redirect to login pages
                    if "login" in result.lower() or "auth" in result.lower():
                        # If redirected to login, consider it valid
                        continue

                    self.assertIn(base_domain, result.lower(),
                                f"Base domain {base_domain} not in result {result}")

    def test_neutralise_redirect(self):
        """
        Test that URLs with redirects are properly resolved to their final destination.
        """
        # Test with a URL that redirects from HTTP to HTTPS
        if redirect_links:
            http_url = redirect_links[0]  # "http://google.com"

            start_time = time.time()
            result = neutralise(http_url)
            duration = time.time() - start_time

            logger.info(f"Neutralized redirect URL in {duration:.3f} seconds: {http_url}")

            # When redirects are resolved, the URL should be different
            # from the original in some way (protocol, www, etc.)
            self.assertNotEqual(result.lower(), http_url.lower(),
                              f"URL {http_url} was not changed after redirect resolution")

    def test_neutralise_malicious(self):
        # Test with actual malicious URL
        url = "https://example.com/?param=value&backfill=hack"

        start_time = time.time()
        result = neutralise(url)
        duration = time.time() - start_time

        logger.info(f"Attempted to neutralize malicious URL in {duration:.3f} seconds: {url}")

        # The real is_mal function should detect this as malicious
        self.assertIsNone(result)

    def test_neutralise_no_protocol(self):
        # Test URL without protocol
        url = "github.com"

        start_time = time.time()
        result = neutralise(url)
        duration = time.time() - start_time

        logger.info(f"Neutralized URL without protocol in {duration:.3f} seconds: {url}")

        # Check that protocol was added and the domain is present
        # Allow for potential trailing slash variations
        normalized_result = result.rstrip('/')
        normalized_expected = "https://github.com"
        self.assertEqual(normalized_result, normalized_expected,
                        f"Expected {normalized_expected}, got {normalized_result}")


if __name__ == '__main__':
    unittest.main()
