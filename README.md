# neturalise-link

## What are the objectives?

- Remove trackers
- Remove referrers
- Identify malicious intent
- Verify URL validity
- Improve URL load speeds

## Getting started

### Prerequisites

- Have python3 installed (e.g. using anaconda/homebrew)
- Have build installed - `python3 -m pip install --upgrade build`

### Building the package

Navigate to root directory of the project and run: `python3 -m build`

Install the package found in `neutralise-link/dist/`
in your repo using `pip3 install` followed by the relative path of the `.tar.gz` package file located in the project.

## How does it work?

Having imported `neutralise-link` you may use the `neutralise` function which takes a URL string as the argument.

By default, the function will return `None` in two cases:

1. The link is invalid
2. The link is deemed malicious

> You may override the 2nd case by calling the function with the optional parameter, `safe=false`.

---

## Example Code

``` python
from neutralise_link import neutralise

def main(url: str) -> str:
    """Validate user URL input for storing."""

    url = neutralise(url=url, safe=True)
    if not url:
        print("URL is malformed or malicious.")
    print("URL is safe.")
```
