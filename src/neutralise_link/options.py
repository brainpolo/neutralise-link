# Copyright (C) 2023-2025 brainpolo
# Author(s): Aditya Dedhia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.


DEFAULT_REQUEST_TIMEOUT = 5
MAX_REDIRECTS = 3  # Maximum number of redirects allowed

# Malicious URL Thresholds -----------------------------------------------------

MAX_URL_LENGTH = 1_000  # Maximum URL length to process before it is flagged
MAX_SUBDOMAINS = 4  # Maximum number of subdomains allowed in a URL
MAX_QUERY_PARAMS = 15  # Maximum number of query parameters allowed in a URL
