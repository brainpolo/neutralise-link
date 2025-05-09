# Copyright (C) 2023-2025 brainpolo
# Author(s): Aditya Dedhia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from urllib.parse import unquote


# Decode percent-encoded ASCII characters that don't need encoding
def selective_unquote(url):
    parts = url.split('?', 1)
    path = unquote(parts[0])
    if len(parts) > 1:
        # Keep query parameters encoded
        return path + '?' + parts[1]
    return path
