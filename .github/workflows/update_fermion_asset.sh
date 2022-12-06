#!/bin/bash

#######
## This needs more work
#######

##
# Auto-update JS docs in about.html
# |_ It may be best to integrate a markdown reader into about this way docs can
#    be ingested from https://github.com/frida/frida-website/blob/master/_i18n/en/_docs/javascript-api.md
##

# Get updated js docs
#docOutput=$(curl -s "https://frida.re/docs/javascript-api/");
#copyStart=$(echo "$docOutput"| grep -n "Table of contents" |awk -F: '{print $1}');
#copyEnd=$(echo "$docOutput"| grep -n "section-nav" |awk -F: '{print $1}');
#newDoc=$(echo "$docOutput" | sed -n "$copyStart,$((copyEnd - 1))p");

##
# Auto-generate version image for about.html
##