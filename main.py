# -*- coding: utf-8 -*-
"""Main module

This module exposes the main procedures available.
The main class initialize an access to VirusTotal interface, to allow API calls.

Todo:
    * Improve error handling
    * If possible, retrieve all possible responses from VirusTotal for FileReport
      to ensure all cases are handled properly
"""
import json
import virustotal_interface


class Main():
    """Class to retrieve reports from VirusTotal and return analysis.

    This class initialize a connection to VirusTotal to execute API calls.
    Different high level analysis on the data received from VirusTotal may be
    implemented here.
    This implementation includes only the public method get_detections_count.
    """
    def __init__(self):
        """Class initialized without args.

        Params:
            self.virustotal (VirustotalInterface): interface to handle API calls
            to VirusTotal.
        """
        self.virustotal = virustotal_interface.VirustotalInterface()

    def get_detections_count(self) -> dict:
        """Retrieves a file report for each hash given in hashes.txt and return the detections count
        
        Note:
            instead of reading a file of hashes, this method can be modified to
            receive a list of hashes.
        
        Args:
            None

        Returns:
            dict: A dictionary in the form of string : int.
            If the count is not available, the key/value pair is string : string,
            with the value representing a description of the error.
        """
        detections_count = {}
        with open('hashes.txt', encoding='utf-8', mode = 'r') as hashes:
            for provided_hash in hashes:
                clean_hash = provided_hash.strip()
                file_report = self.virustotal.file_report_for(clean_hash)
                detections_count[clean_hash] = self._update_detections_count(file_report)
        return detections_count

    def _update_detections_count(self, file_report: dict) -> int | str:
        if 'error' in file_report.keys():
            return file_report['error']['code']
        return self._extract_count(file_report)

    def _extract_count(self, file_report: dict) -> int | str:
        try:
            report = file_report['data']['attributes']['last_analysis_stats']['malicious']
        except KeyError:
            report = 'Count not available'
        return report

if __name__ == '__main__':
    result = Main().get_detections_count()
    print("The current total number of detections for the provided list of hashes is:")
    print(json.dumps(result, indent=2))
