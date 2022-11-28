# This script needs to be run at root of repo

import requests
import subprocess
import tarfile
import io
import os
import time

from _github_api_helper import github_api_get

## It's now directly included instead of manually updating

# print("Updating frida.d.ts...")
# pkgInfo = requests.get('https://registry.npmjs.org/@types/frida-gum').json()
# latestVer = pkgInfo["dist-tags"]['latest']
# pkgTarUrl = pkgInfo['versions'][latestVer]['dist']['tarball']
# pkgTarContent = requests.get(pkgTarUrl).content
# with tarfile.open(fileobj=io.BytesIO(pkgTarContent), mode='r:gz') as pkgTar:
#     fridaDef = pkgTar.extractfile('frida-gum/index.d.ts').read()

# with open('./Fermion/src/lang/frida.d.ts', 'wb') as f:
#     f.write(fridaDef)


print("Updating javascript-api.md...")
changes = github_api_get('https://api.github.com/repos/frida/frida-website/commits?path=_i18n/en/_docs/javascript-api.md')
commitDate = changes[0]['commit']['committer']['date']

# With CRLF or not, that a problem
with open('./Fermion/src/docs/readme.txt', 'wb') as f:
    f.write((
        "Source      : https://github.com/frida/frida-website/blob/master/_i18n/en/_docs/javascript-api.md\n" + \
        "Doc Version : Last commit " + commitDate).encode())

jsReadme = requests.get('https://github.com/frida/frida-website/raw/main/_i18n/en/_docs/javascript-api.md').content
with open('./Fermion/src/docs/javascript-api.md', 'wb') as f:
    f.write(jsReadme)
