# neturalise-link

## What are the objectives?

- Remove trackers
- Remove referrers
- Identify malicious intent
- Verify URL validity
- Improve URL load speeds

## How does it work?

Having imported `neutralise-link` you may use the `neutralise` function which takes a URL string as the argument.

The function is designed to return either a string URL or None. It is recommended to
use the returned URL value in place of the original URL as this is the neutralised
version of the URL.

By default, the function will return `None` in two cases:

1. The link is invalid
2. The link is deemed malicious

> You may override the 2nd case by calling the function with the optional parameter, `safe=false`.

---

## Example Code

```python
from neutralise_link import neutralise

def main(url: str) -> str:
    """Validate user URL input for storing."""

    url = neutralise(url=url, safe=True)
    if not url:
        print("URL is malformed or malicious.")
    print("URL is safe.")
```

## Contributing

### Prerequisites

- Have python 3.10 installed on system (e.g. using anaconda/homebrew)

### Environment Setup

1. Set up a virtual environment using `python -m venv venv`
2. Activate the virtual environment using `source venv/bin/activate`
3. Install development dependencies using `pip install -r requirements.txt`

### Running tests

It is important to ensure that ALL tests pass before submitting a PR.

```bash
python -m unittest discover -s tests
```

It is also imperative that coverage is above 90% before submitting a PR. Validate this by running:

```bash
coverage run -m tests.test_neutralise && coverage report && coverage html
```

### Building the package

1. Navigate to root directory of the project and run: `python -m build`

2. Install the package found in `neutralise-link/dist/`
   in your repo using `pip install` followed by the relative path of the `.tar.gz` package file located in the project. For example:

```bash
pip install dist/neutralise_link-0.1.0.tar.gz
```

### Uploading to PyPI

Ensure that the package is built and the dist directory is populated. Then run:

```bash
python -m twine upload dist/*
```
