import requests
import re
import json
import os

from _github_api_helper import github_api_get

# Get latests Frida version
fridaLatestRelease = github_api_get('https://api.github.com/repos/frida/frida/releases/latest')
fridaVer = fridaLatestRelease['tag_name']

# Get latests Frida Gum version
fridaGumVer = requests.get('https://registry.npmjs.org/@types/frida-gum').json()['dist-tags']['latest']

# Get Electron ver from package index
with open(os.path.dirname(os.path.abspath(__file__)) + "/../../" + "Fermion/package.json", 'r') as f:
    fridaElectronVer = json.load(f)['dependencies']['electron']

# Get package ver from package index
with open(os.path.dirname(os.path.abspath(__file__)) + "/../../" + "Fermion/package.json", 'r') as f:
    fermionVer = json.load(f)['version']
fermionVer = fermionVer.split("-")[0]
fermionTag = "%s" % (fermionVer)

import os, json
if 'GITHUB_OUTPUT' in os.environ:
    f = open(os.environ['GITHUB_OUTPUT'], "a")
    output = lambda x: f.write(x)
else:
    output = print

print("[?] Build on Electron: ", fridaElectronVer)
print("[?] Latest Frida version: ", fridaVer)

output("FRIDA_VER=%s\n" % fridaVer)
output("FRIDA_GUM_VER=%s\n" % fridaGumVer)
output("FRIDA_ELECTRON=%s\n" % fridaElectronVer)
output("FERMION_TAG=%s\n" % fermionTag)
