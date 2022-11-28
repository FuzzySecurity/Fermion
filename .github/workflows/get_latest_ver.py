import requests
import re
import json
import os

from _github_api_helper import github_api_get

fridaLatestRelease = github_api_get('https://api.github.com/repos/frida/frida/releases/latest')
fridaVer = fridaLatestRelease['tag_name']
fridaGumVer = requests.get('https://registry.npmjs.org/@types/frida-gum').json()['dist-tags']['latest']

fridaElectronModVer = {}
fridaElectronUrl = {}
for asset in fridaLatestRelease['assets']:
    assetInfo = re.findall("frida-v[^-]+?-electron-v([0-9]+?)-([^-]+?)-([^-]+?).tar.gz", asset['name'])
    if not assetInfo:
        continue

    #triple = tuple(assetInfo[0][1:3])
    triple = '-'.join(assetInfo[0][1:3])
    modver = assetInfo[0][0]

    print("Found frida-electron:", triple, modver)
    fridaElectronModVer[triple] = modver
    fridaElectronUrl[triple] = asset['browser_download_url']

# print(fridaElectronModVer)

FRIDA_TRIPLE_BLACKLIST = ['freebsd', 'ia32', 'arm']
fridaElectronModVer = {k:v for k,v in fridaElectronModVer.items() if not any(c in str(k) for c in FRIDA_TRIPLE_BLACKLIST)}
print(fridaElectronModVer)


fridaTriples = list(fridaElectronModVer.keys())
fridaTriplesOS = {
    triple: {"darwin":"macos-latest","win32":"windows-latest","linux":"ubuntu-latest"}[triple.split('-')[0]] for triple in fridaTriples
}

fridaElectronVer = {}
electronVers = requests.get("https://github.com/electron/releases/raw/master/lite.json").json()
for ver in electronVers:
    if ver['prerelease'] != False:
        continue
    for triple, modver in fridaElectronModVer.items():
        if triple in fridaElectronVer:
            continue
        if str(ver['deps']['modules']) != str(modver):
            continue
        fridaElectronVer[triple] = ver['version']

with open(os.path.dirname(os.path.abspath(__file__)) + "/../../" + "Fermion/package.json", 'r') as f:
    fermionVer = json.load(f)['version']

fermionVer = fermionVer.split("-")[0]

fermionTag = "%s-frida%s-gumjs%s" % (fermionVer, fridaVer, fridaGumVer)

# print("fridaVer: ", fridaVer)
# print("fridaGumVer: ", fridaGumVer)
# print("fridaElectronVer: ", fridaElectronVer)
import os, json
if 'GITHUB_OUTPUT' in os.environ:
    f = open(os.environ['GITHUB_OUTPUT'], "a")
    output = lambda x: f.write(x)
else:
    output = print

output("FRIDA_VER=%s\n" % fridaVer)
output("FRIDA_GUM_VER=%s\n" % fridaGumVer)
output("FRIDA_TRIPLES=%s\n" % json.dumps(fridaTriples))
output("FRIDA_TRIPLES_OS=%s\n" % json.dumps(fridaTriplesOS))
output("FRIDA_ELECTRON=%s\n" % json.dumps(fridaElectronVer))
output("FRIDA_ELECTRON_ASSET=%s\n" % json.dumps(fridaElectronUrl))
output("FERMION_TAG=%s\n" % fermionTag)
