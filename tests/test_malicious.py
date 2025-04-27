import unittest
import sys
import os

# Add the parent directory to sys.path to access the package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.neutralise_link.main import is_mal


class TestMaliciousURLs(unittest.TestCase):

    def test_safe_urls(self):
        """Test that normal URLs are not flagged as malicious."""
        safe_urls = [
            "https://google.com",
            "https://example.com/page?param=value",
            "https://github.com/user/repo",
            "https://en.wikipedia.org/wiki/Python_(programming_language)",
            "https://stackoverflow.com/questions/tagged/python?tab=Newest",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://apple.com/iphone",
            "https://amazon.com/s?k=laptop",
            "https://news.ycombinator.com/",
        ]

        for url in safe_urls:
            with self.subTest(url=url):
                self.assertFalse(is_mal(url), f"URL incorrectly flagged as malicious: {url}")

    def test_malicious_original(self):
        """Test the original backfill check."""
        self.assertTrue(is_mal("https://example.com/?param=value&backfill=something"))

    def test_malicious_injection(self):
        """Test detection of injection attempts."""
        injection_urls = [
            "https://example.com/page?param=<script>alert('XSS')</script>",
            "https://example.com/javascript:alert('XSS')",
            "https://example.com/page?param=javascript:alert(1)",
            "https://example.com/page?param=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "https://example.com/page?param=document.cookie",
            "https://example.com/page?param=eval(alert(1))",
        ]

        for url in injection_urls:
            with self.subTest(url=url):
                self.assertTrue(is_mal(url), f"Malicious URL not detected: {url}")

    def test_malicious_path_traversal(self):
        """Test detection of path traversal attempts."""
        traversal_urls = [
            "https://example.com/../../../etc/passwd",
            "https://example.com/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "https://example.com/page?file=../../../etc/passwd",
        ]

        for url in traversal_urls:
            with self.subTest(url=url):
                self.assertTrue(is_mal(url), f"Path traversal not detected: {url}")

    def test_malicious_command_injection(self):
        """Test detection of command injection attempts."""
        cmd_injection_urls = [
            "https://example.com/index.php?cmd=cat%20/etc/passwd",
            "https://example.com/page.php?exec=ls%20-la",
            "https://example.com/api.php?system=rm%20-rf%20/",
        ]

        for url in cmd_injection_urls:
            with self.subTest(url=url):
                self.assertTrue(is_mal(url), f"Command injection not detected: {url}")

    def test_malicious_excessive(self):
        """Test detection of excessive patterns."""
        # Create a URL with 20 query parameters
        params = "&".join([f"param{i}=value{i}" for i in range(20)])
        excessive_params_url = f"https://example.com/page?{params}"

        # Create a URL with 5 subdomains
        excessive_subdomains_url = "https://a.b.c.d.e.f.example.com"

        # Create an extremely long URL
        very_long_url = "https://example.com/?" + "x" * 2500

        self.assertTrue(is_mal(excessive_params_url), "Excessive parameters not detected")
        self.assertTrue(is_mal(excessive_subdomains_url), "Excessive subdomains not detected")
        self.assertTrue(is_mal(very_long_url), "Extremely long URL not detected")


if __name__ == '__main__':
    unittest.main()
