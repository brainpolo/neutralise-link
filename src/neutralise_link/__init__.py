# Copyright (C) 2023 Aditya Dedhia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.


from .main import is_mal, is_valid, rem_refs, rem_trackers, compactify

from .logger import logger


def neutralise(url: str, safe=True) -> str:
    """
    Handles the total cleansing of a URL input
    """
    url = url.strip()
    if not url.startswith("http"):
        url = "https://" + url
    if safe and is_mal(url):  # * Default safe mode can be overriden
        logger.info("Malicious URL detected: %s", url)
        return None
    if not is_valid(url):
        logger.info("Invalid URL detected: %s", url)
        return None

    logger.info("URL is valid and will be processed.")

    url = rem_refs(url)
    url = rem_trackers(url)
    if not is_valid(url):
        logger.info("Invalid URL after filtering referrers and trackers: %s", url)
        return None
    minified_url = compactify(url)

    if not is_valid(minified_url):
        logger.info("Invalid URL after minifying: %s", url)
        return url
    return minified_url
