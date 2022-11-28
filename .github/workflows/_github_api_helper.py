import requests
import os
import time

def github_api_get(url):
    for i in range(3):
        changes = None
        hdrs = {}
        if 'GITHUB_TOKEN' in os.environ: # Github will sometimes rate limit if we don't pass token
            print("Using GITHUB_TOKEN!")
            hdrs = {
                "Authorization": os.environ['GITHUB_TOKEN']
            }
        rjson = None
        try:
            r = requests.get(url, headers=hdrs)
            rjson = r.json()
            if r.status_code != 200:
                raise Exception()
        except:
            print("Error occurred in GitHub API, Retrying. Server return: %s" % rjson)
            time.sleep(2.0)
            if i == 2:
                raise
        else:
            return rjson
    
    # should never get here