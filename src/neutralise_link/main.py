# Copyright (C) 2023-2025 brainpolo
# Author(s): Aditya Dedhia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.


import re
import requests
import random

from .utils import selective_unquote
from .options import (
    DEFAULT_REQUEST_TIMEOUT,
    MAX_URL_LENGTH,
    MAX_SUBDOMAINS,
    MAX_QUERY_PARAMS,
    MAX_REDIRECTS
)

# Known malicious parameters
bad_params = [
    "&backfill=",           # Original check
    "eval(",                # JavaScript execution
    "document.cookie",      # Cookie stealing
    "javascript:",          # JavaScript protocol
    "data:",                # Data URI scheme often used in XSS
    "vbscript:",            # VBScript protocol
    "onload=",              # Event handler injection
    "onerror=",             # Event handler injection
    "<script",              # Script tag injection
    "%3cscript",            # URL encoded script tag
    "document.location",    # Location hijacking
    ".php?cmd=",            # Command injection in PHP
    ".php?exec=",           # Command execution in PHP
    ".php?system=",         # System command in PHP
    "/?page=http",          # Remote file inclusion
    "/?file=http",          # Remote file inclusion
    "/.git/",               # Exposed git repository
    "/.env",                # Exposed environment file
    "/wp-config.php",       # WordPress config exposure
    "/config.php?",         # PHP config exposure
    "/admin/",              # Admin panel probing
    "/xmlrpc.php",          # WordPress XML-RPC
    "/?s=index/",           # ThinkPHP exploit pattern
    "/shell",               # Shell access attempt
    "/cmd",                 # Command execution attempt
    "/../",                 # Directory traversal
    "%2e%2e%2f",            # URL encoded directory traversal
    "etc/passwd",           # Common file disclosure target
    "win.ini",              # Windows configuration file
]


# Common User-Agents for different browsers and platforms
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/122.0.0.0',
]


def get_random_user_agent() -> str:
    """
    Returns a random User-Agent from a list of common ones.
    This helps avoid detection and improves reliability.
    """
    return random.choice(USER_AGENTS)


def rem_refs(url: str) -> str:
    """
    Removes the referrer from a URL. Referrers are used to track the source of a
    user's visit to a website.

    Args:
        url (str): The URL to remove referrers from

    Returns:
        str: The URL with the referrers removed
    """

    # * Generic UTM parameters
    source_pattern = r"&sourceid=.*?(?=&|$)"
    url = re.sub(source_pattern, "&", url)

    client_pattern = r"&sclient=.*?(?=&|$)"
    url = re.sub(client_pattern, "", url)

    utm_source_pattern = r"&utm_source=.*?(?=&|$)"
    url = re.sub(utm_source_pattern, "&", url)

    utm_medium_pattern = r"&utm_medium=.*?(?=&|$)"
    url = re.sub(utm_medium_pattern, "&", url)

    utm_campaign_pattern = r"&utm_campaign=.*?(?=&|$)"
    url = re.sub(utm_campaign_pattern, "&", url)

    # * Specific UTM parameters

    # Facebook click ID
    fbclid_pattern = r"&fbclid=.*?(?=&|$)"
    url = re.sub(fbclid_pattern, "&", url)

    # Google click ID
    gclid_pattern = r"&gclid=.*?(?=&|$)"
    url = re.sub(gclid_pattern, "&", url)

    # More UTM parameters
    utm_term_pattern = r"&utm_term=.*?(?=&|$)"
    url = re.sub(utm_term_pattern, "&", url)
    utm_content_pattern = r"&utm_content=.*?(?=&|$)"
    url = re.sub(utm_content_pattern, "&", url)

    # Microsoft Click ID
    msclkid_pattern = r"&msclkid=.*?(?=&|$)"
    url = re.sub(msclkid_pattern, "&", url)

    # TikTok tracking
    ttclid_pattern = r"&ttclid=.*?(?=&|$)"
    url = re.sub(ttclid_pattern, "&", url)

    return url


def rem_trackers(url: str) -> str:
    """
    Removes the trackers from a URL. Trackers are used to track the user's
    visit to a website.

    Args:
        url (str): The URL to remove trackers from

    Returns:
        str: The URL with the trackers removed
    """

    # * Generic tracking parameters
    event_id_pattern = r"&ei=.*?(?=&|$)"
    url = re.sub(event_id_pattern, "&", url)

    googl_aqs_pattern = r"&aqs=.*?(?=&|$)"
    url = re.sub(googl_aqs_pattern, "&", url)

    viewer_data_pattern = r"&ved=.*?(?=&|$)"
    url = re.sub(viewer_data_pattern, "&", url)

    user_act_pattern = r"&uact=.*?(?=&|$)"
    url = re.sub(user_act_pattern, "&", url)

    click_pos_pattern = r"&gs_lcp=.*?(?=&|$)"
    url = re.sub(click_pos_pattern, "&", url)

    mkt_token_pattern = r"&mkt_tok=.*?(?=&|$)"
    url = re.sub(mkt_token_pattern, "&", url)

    # * Specific tracking parameters

    # Amazon tracking
    tag_pattern = r"&tag=.*?(?=&|$)"
    url = re.sub(tag_pattern, "&", url)

    # LinkedIn tracking
    li_fat_id_pattern = r"&li_fat_id=.*?(?=&|$)"
    url = re.sub(li_fat_id_pattern, "&", url)

    # Hubspot tracking
    _hsenc_pattern = r"&_hsenc=.*?(?=&|$)"
    url = re.sub(_hsenc_pattern, "&", url)
    _hsmi_pattern = r"&_hsmi=.*?(?=&|$)"
    url = re.sub(_hsmi_pattern, "&", url)

    # YouTube tracking
    feature_pattern = r"&feature=.*?(?=&|$)"
    url = re.sub(feature_pattern, "&", url)

    # Twitter/X tracking parameter
    twclid_pattern = r"&twclid=.*?(?=&|$)"
    url = re.sub(twclid_pattern, "&", url)

    return url


def compactify(url: str) -> str:
    """
    Removes the visual elements of a URL primarily for cosmetic purposes.
    Streamlines URLs for cleaner presentation and sharing.

    Args:
        url (str): The URL to compactify

    Returns:
        str: The compactified URL
    """

    # Basic compactification (safe)
    # ----------------------------

    # Remove www. subdomain
    url = url.replace("www.", "")

    # Remove unnecessary default ports
    url = re.sub(r":80/", "/", url)  # HTTP default port
    url = re.sub(r":443/", "/", url)  # HTTPS default port

    # Remove trailing slashes
    url = url.rstrip("/")

    # Process query parameters - handle empty query string
    # Remove empty query string completely
    url = re.sub(r"\?$", "", url)

    # Process query parameters with content
    if "?" in url:
        base_url, query = url.split("?", 1)

        # Remove empty parameters
        clean_params = []
        for param in query.split("&"):
            if param and ("=" not in param or (param.split("=", 1)[1] != "")):
                # Keep params without = and params with non-empty values
                clean_params.append(param)

        # Reconstruct URL with clean parameters
        if clean_params:
            url = base_url + "?" + "&".join(clean_params)
        else:
            url = base_url  # No parameters left

    # Normalize percent encoding
    url = selective_unquote(url)

    # Standardize domain case (lowercase)
    domain_pattern = r"(https?://)(.*?)(/|$)"
    url = re.sub(domain_pattern, lambda m: m.group(1) + m.group(2).lower() + m.group(3), url)

    # Advanced compactification (more aggressive)
    # ------------------------------------------
    # Remove consecutive slashes in path
    url = re.sub(r"(?<!:)/{2,}", "/", url)

    # Collapse relative path elements
    segments = []
    for segment in url.split('/'):
        if segment == '..':
            if segments and segments[-1] not in ('', '..'):
                segments.pop()
            else:
                segments.append(segment)
        elif segment != '.' or not segments:
            segments.append(segment)
    url = '/'.join(segments)

    # Final cleanup - ensure we don't have empty query strings
    url = re.sub(r"\?$", "", url)

    return url


def is_mal(url: str) -> bool:
    """
    Checks if a URL appears to be malicious.

    Args:
        url (str): The URL to check

    Returns:
        bool: True if the URL is potentially malicious, False otherwise
    """

    if len(url) > MAX_URL_LENGTH:
        return True

    url_lower = url.lower()

    if any(pattern in url_lower for pattern in bad_params):
        return True

    # Check for excessive subdomains (potential phishing)
    domain_part = url_lower.split("//", 1)[-1].split("/", 1)[0]
    if domain_part.count(".") > MAX_SUBDOMAINS:
        return True

    # Check for excessive query parameters (potential SQLi or CSRF)
    if url.count("&") > MAX_QUERY_PARAMS:
        return True

    return False


def is_valid(url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT) -> str | None:
    """
    Checks if a URL is valid by making a HEAD request.
    If the server does not allow HEAD requests, it will make a GET request.

    If neither requests result in a successful 2xx response, the URL is invalid,
    with exceptions for 401 and 403 responses which indicate the URL exists
    but requires authentication.

    Args:
        url (str): The URL to check.
        timeout (int): The timeout for the request.

    Returns:
        str | None: The final URL destination if valid, None otherwise.
    """

    ACCEPTED_NON_2XX_STATUS_CODES = [
        301,  # Moved Permanently
        302,  # Found (Temporary Redirect)
        307,  # Temporary Redirect
        308,  # Permanent Redirect
        401,  # Unauthorized
        403,  # Forbidden
        429,  # Too Many Requests
        503,  # Service Unavailable (WAF interception)
        504,  # Gateway Timeout (WAF interception)
    ]

    # Basic request headers
    headers = {
        'User-Agent': get_random_user_agent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    }

    # Create a session to control redirect behavior
    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS

    try:
        # First try a HEAD request with controlled redirects
        try:
            response = session.head(
                url,
                headers=headers,
                allow_redirects=True,
                timeout=timeout
            )

            # For authentication-required pages, consider them valid
            if response.status_code in ACCEPTED_NON_2XX_STATUS_CODES:
                return response.url  # Return the final URL after redirects

            response.raise_for_status()
            return response.url  # Return the final URL after redirects

        except requests.exceptions.HTTPError as e:
            # If we get a 405 Method Not Allowed, try a GET request
            if e.response.status_code == 405:
                response = session.get(
                    url,
                    headers=headers,
                    allow_redirects=True,
                    timeout=timeout,
                    stream=True  # Prevent downloading entire content
                )

                # For authentication-required pages, consider them valid
                if response.status_code in ACCEPTED_NON_2XX_STATUS_CODES:
                    final_url = response.url  # Capture the final URL
                    response.close()
                    return final_url

                response.raise_for_status()
                final_url = response.url  # Capture the final URL
                response.close()
                return final_url

            # Check if it's an accepted status code
            if e.response.status_code in ACCEPTED_NON_2XX_STATUS_CODES:
                return e.response.url  # Return the final URL after redirects

            raise e  # ? Some other non-accepted HTTP error

    except (requests.exceptions.RequestException,
            requests.exceptions.TooManyRedirects) as e:
        # If request fails completely or too many redirects, FAIL URL
        return None
