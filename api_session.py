# -*- coding: utf-8 -*-
"""API Session module

This module handles any type of API call; at the moment, the key library is
requests. A dedicate module to handle API calls improves logging and separates
the logic to manage the library from the actual needs for requests, making it
easy to switch to different libraries to manage API if needed.

Todo:
    * Implement additional requests type (GET, POST, DELETE...) or provide a
    general method, with the possibility to specify the request type
    * wait time for API calls could be parametrized
"""
from urllib.parse import urljoin
import requests


class ApiSession():
    """Class handling API sessions

    The scope of this class is to adapt the common part of an API request (uri,
    headers, body, options) to the library used to execute them: different libraries
    will require the same data, maybe provided in different forms.
    Also, it can provide low-level logging (being a single entry point for any
    API request), low level call management and additional low level details.
    """
    def __init__(self, host: str):
        """Class initialized with an host.

        Args:
            host (str): the target host for API calls.

        Params:
            self.host (str): the host.
        """
        self.host = host

    def get_request(self, endpoint: str, headers: dict = None) -> dict:
        """Execute a GET request.

        implements the code to execute a basic get request to an endpoint.

        Note:
            May require additional features to be able to execute *any* GET request.

        Args:
            endpoint (str): the endpoint for the request. Note that it must not
            start with a /; the endpoint is joined with the host provided as
            instance variable.
            headers (dict): a dictionary containing all the values required in
            the headers
        """
        response = requests.get(self._url(endpoint), headers = headers, timeout = 2)
        return response.json()

    def _url(self, endpoint: str) -> str:
        return urljoin(self.host, endpoint)
