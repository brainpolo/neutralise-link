# Copyright (C) 2023 Aditya Dedhia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.


import re
import requests


def rem_refs(url: str) -> str:
    """
    Removes the referrer from a URL
    """

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
    return url


def rem_trackers(url: str) -> str:
    """
    Removes the trackers from a URL
    """

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
    return url


def compactify(url: str) -> str:
    """
    Removes the visual elements of a URL primarily for cosmetic purposes.
    If fails, returns the former minified URL.
    """

    url = url.replace("www.", "")

    return url


def is_mal(url: str) -> bool:
    if "&backfill=" in url:
        return True
    return False


def is_valid(url: str) -> bool:
    try:
        response = requests.head(url)
        response.raise_for_status()  # * Raised if status is 4xx, 5xx
        return True
    except requests.exceptions.RequestException:
        return False
