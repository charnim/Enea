import time
import json
import requests
import datetime
import pprint
import sys
import copy


class VirusTotal(object):

    """A parser for VirusTotal,

    Args:
          api_key = The api key of virus total
          resource = item to query
          url = Query type, ip/hash/domain ect"""

    def __init__(self, resource, api_key, url='', request_is_post=False):

        params = {'apikey': api_key, 'resource': resource, 'allinfo': 'true', 'scan': 1}

        self.Url = url

        self.Resource = resource

        while True:

            try:

                if request_is_post:

                    answer = requests.post(url, params=params)

                else:

                    answer = requests.get(url, params=params)

            # Need to retry

                self.Response = answer.json()

            # Simply checks if the response is not [] which may happen if None or '' is sent to VT

                int(self.Response['response_code'])

                break

            # Error handling section

            except TypeError:

                print("The resource: '{0.Resource}' is not valid, please make sure you are uploading the right item".format(self))

                time.sleep(15)

            except json.decoder.JSONDecodeError:

                print("\nVirus Total request limit per minute reached, waiting.\n")

                time.sleep(30)

            except requests.exceptions.ConnectionError:

                print("\nNo Internet Connection, will retry in 30 seconds.\n")

                time.sleep(30)

        # Will return code 0 if this is a rescan

        if url != 'https://www.virustotal.com/vtapi/v2/file/rescan':

            # Will check if response_code is 1, otherwise print error

            if self.Response['response_code'] != 1:

                self.ResponseCode = self.Response['response_code']

            else:

                # If response is legit and no errors, parse data

                self.Scans = self.Response['scans']

                self.Total = self.Response['total']

                self.ScanDate = self.Response['scan_date']

                self.AgeInSeconds = int(datetime.datetime.utcnow().timestamp() - time.mktime(datetime.datetime.strptime(self.ScanDate, "%Y-%m-%d %H:%M:%S").timetuple()))

                try:

                    self.Positives = self.Response['positives']

                except AttributeError:

                    print(self.Response)

                    sys.exit(0)

                self.ScanLink = self.Response['permalink']

                self.Message = self.Response['verbose_msg']

                self.ResponseCode = self.Response['response_code']

                self.ScanId = self.Response['scan_id']

                # If there are files then get hashes

                if self.Response.get('sha256'):

                    self.MD5 = self.Response['md5']

                    self.SHA256 = self.Response['sha256']

                    self.SHA1 = self.Response['sha1']

        else:

            self.ResponseCode = 0

    def compressor(self):

        attribute_list = copy.deepcopy(self.__dict__)

        try:

            for attribute in attribute_list:

                if attribute == 'Scans':

                    for vendor in attribute_list[attribute]:

                        if attribute_list[attribute][vendor]['detected'] is True:

                            del self.__dict__[attribute][vendor]['version']

                            del self.__dict__[attribute][vendor]['update']

                        else:

                            del self.__dict__[attribute][vendor]

                elif attribute == 'ResponseCode':

                    pass

                elif attribute == 'Total':

                    pass

                elif attribute == 'Positives':

                    pass

                elif attribute == 'AgeInSeconds':

                    pass

                else:

                    self.__delattr__(attribute)

        except KeyError:

            pass

    def __str__(self):

        pp = pprint.PrettyPrinter(indent=4)

        return str(pp.pprint(self.Response))


class VirusTotalUrl(VirusTotal):

    def __init__(self, resource, api_key):

        super().__init__(resource=resource, url='https://www.virustotal.com/vtapi/v2/url/report', api_key=api_key)


class VirusTotalHash(VirusTotal):

    def __init__(self, resource, api_key):

        super().__init__(resource=resource, url='https://www.virustotal.com/vtapi/v2/file/report', api_key=api_key)


class VirusTotalHashRescan(VirusTotal):

    def __init__(self, resource, api_key):

        super().__init__(resource=resource, url='https://www.virustotal.com/vtapi/v2/file/rescan', api_key=api_key, request_is_post=True)








