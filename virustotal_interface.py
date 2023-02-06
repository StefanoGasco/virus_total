# -*- coding: utf-8 -*-
""" Interface to work with VirusTotal API

This module includes all the functionalities to execute API request to VirusTotal API

Todo:
    * Implement checks for limit 500 calls per day
    * Ensure limits (4 calls per second, 500 calls per day) are respected even if
      multiple instances of the class are open, or the code is ran multiple times.
"""
import time
import api_session


class VirustotalInterface():
    """Class to manage API calls to VirusTotal.

    This class manages all the details for interacting with VirusTotal API:
    opening the session, avoiding call overflow, managing the secrets (api key).
    To decrease coupling, the class isn't aware of how it is used, and is agnostic
    about which library is used to execute requests.

    Note:
        This class can avoid call overflow if it's instantiated once. Additional
        development is required if multiple class' instances are expected.
        Also, VirusTotal imposes a limit of 500 calls per day, which may require
        an additional external control to avoid reaching the limit.
    """
    def __init__(self):
        """Class initialized without args.

        Params:
            self.api_key (str): the api key for VirusTotal.
            self.session (ApiSession): Session managing the API calls
            self.call_time_limit (float): minimum time frame between calls, in seconds
            self.last_call_time (time): datestamp of last call executed
        """
        self.api_key = self._read_secret()
        self.session = api_session.ApiSession('https://www.virustotal.com/')
        self.call_time_limit = 1/4
        self.last_call_time = None

    def file_report_for(self, provided_hash: str) -> dict:
        """Retrieve a file report for a provided hash.

        The call is executed based on the documentation at
        https://developers.virustotal.com/reference/file-info. The provided hash is implemented
        in the endpoint, the api-key must be provided in the header. It also tracks when the
        API calls are executed, and eventually wait to ensure the minimum time frame
        is respected.

        Args:
            provided_hash (str): the hash to identify the report do retrieve
        
        Returns:
            dict: the report for the provided hash
        """
        endpoint = f"api/v3/files/{provided_hash}"
        headers = {
            "accept": "application/json",
            "x-apikey": f"{self.api_key}"
        }
        self._avoid_call_overload()
        response = self.session.get_request(endpoint, headers = headers)
        self.last_call_time = time.time()
        return response

    def _read_secret(self) -> str:
        with open('api_key.txt', encoding='utf-8', mode = 'r') as secret:
            return secret.read()

    def _avoid_call_overload(self) -> None:
        if self.last_call_time:
            elapsed_time = time.time() - self.last_call_time
            if elapsed_time < self.call_time_limit:
                time.sleep(self.call_time_limit - elapsed_time)
