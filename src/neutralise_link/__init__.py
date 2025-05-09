# Copyright (C) 2023-2025 brainpolo
# Author(s): Aditya Dedhia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from .logger import logger

from .main import is_mal, is_valid, rem_refs, rem_trackers, compactify


def neutralise(url: str, safe=True, check_valid=True) -> str:
    """
    Handles the total cleansing of a URL input.

    By default, the method will only return a URL if it is both safe AND valid.

    For higher performance scenarios where you are certain the URL is safe and/or
    you do not need to check for URL validity, you can set the optional flags
    to False.

    NOTE: If you skip the validity check, the URL returned may not be in its
    purest form as redirects may still be present.

    Args:
        url (str): The URL to be cleansed.
        safe (bool): Whether to validate the URL as safe.
        check_valid (bool): Whether to perform validity checks with HTTP requests.

    Returns:
        str: The cleansed URL.
    """
    url = url.strip()

    # * Validate that the protocol is present.
    if not url.startswith("http"):
        url = "https://" + url

    # * Validate that the URL is safe if safe mode is enabled.
    if safe and is_mal(url):  # * Default safe mode can be overriden
        logger.info("Malicious URL detected: %s", url)
        return None

    # * Remove referrers and trackers.
    url = rem_refs(url)
    url = rem_trackers(url)

    # * Compactify the URL.
    url = compactify(url)

    # * Final validity check can also be skipped
    if check_valid:
        url = is_valid(url)
        if not url:
            logger.info("Invalid URL: %s", url)
            return None

    return url
