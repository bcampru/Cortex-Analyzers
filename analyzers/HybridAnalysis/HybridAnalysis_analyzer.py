#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
According to data from official site [1], VxStream Sandbox Public API allows you to analyze:

- hash
- filename
- host / ip (some problems on API side for now)
- domain / fqdn (some problems on API side for now)

[1] https://www.hybrid-analysis.com/apikeys/info
"""

import hashlib
import requests
import time

from cortexutils.analyzer import Analyzer


class VxStreamSandboxAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.basic_url = 'https://www.hybrid-analysis.com/api/v2'
        self.api_key = self.get_param(
            'config.key', None, 'VxStream Sandbox API key is missing')
        self.headers = {'User-Agent': 'VxStream', 'api-key': self.api_key}

    def summary(self, raw_report):
        taxonomies = []

        # default values
        report_verdict = 'no specific threat'
        namespace = "HybridAnalysis"
        predicate = "Threat level"
        value = "Unknown"

        # define json keys to loop
        minireports = raw_report.get('results')
        if 'result' in minireports:
            # get first report with not Null verdict
            for minireport in minireports.get('result'):
                if minireport.get('verdict') is not None:
                    report_verdict = minireport.get('verdict')
                    break
        else:
            if minireports.get('verdict') is not None:
                report_verdict = minireports.get('verdict')
            if minireports.get('threat_score') is not None:
                value = minireports.get('threat_score')

        if report_verdict == 'malicious':
            level = 'malicious'
        elif report_verdict == 'suspicious':
            level = 'suspicious'
        elif report_verdict == 'whitelisted':
            level = 'safe'
            value = "Whitelisted"
        elif report_verdict == 'no specific threat':
            level = 'info'

        taxonomies.append(self.build_taxonomy(
            level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):

        try:
            if self.data_type == 'hash':
                hash = self.get_param('data', None, 'Hash is missing')
                if len(hash) != 64:
                    query_url = '/search/hash'
                    query_data = {'hash': hash}
                    url = str(self.basic_url) + str(query_url)
                    error = True
                    while error:
                        r = requests.post(url, data=query_data,
                                          headers=self.headers, verify=True)
                        if not r.ok:
                            if "Exceeded maximum API requests per minute(5)" in r.json().get('message'):
                                time.sleep(60)
                            else:
                                self.error(r.json().get('message'))
                        else:
                            error = False
                    hash = r.json()[0]['sha256']
                query_url = '/overview/{}/summary'.format(hash)

            elif self.data_type == 'file':
                hashes = self.get_param('attachment.hashes', None)

                if hashes is None:
                    filepath = self.get_param('file', None, 'File is missing')
                    hash = hashlib.sha256(
                        open(filepath, 'rb').read()).hexdigest()
                else:
                    # find SHA256 hash
                    hash = next(h for h in hashes if len(h) == 64)
                query_url = '/overview/{}/summary'.format(hash)
            elif self.data_type == 'filename':
                query_url = '/search/terms'
                query_data = {'filename': self.get_param(
                    'data', None, 'Filename is missing')}
            else:
                self.notSupported()

            url = str(self.basic_url) + str(query_url)

            error = True
            while error:
                if self.data_type == 'filename':
                    r = requests.post(url, data=query_data,
                                      headers=self.headers, verify=True)
                else:
                    r = requests.get(url, headers=self.headers, verify=True)
                if not r.ok:
                    if "Exceeded maximum API requests per minute(5)" in r.json().get('message'):
                        time.sleep(60)
                    else:
                        self.error(r.json().get('message'))
                else:
                    error = False

            self.report({'results': r.json()})
        except ValueError as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    VxStreamSandboxAnalyzer().run()
