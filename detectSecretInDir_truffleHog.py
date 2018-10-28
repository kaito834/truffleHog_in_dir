#!/usr/bin/env python
# coding: utf-8

import os
import sys
from truffleHog_in_dir import truffleHog_in_dir

def main():
    dirStr = sys.argv[1]

    if not os.path.exists(dirStr):
        print("[!] \"{0}\" isn't found.".format(dirStr))
        exit(1)
    if not os.path.isdir(dirStr):
        print("[!] \"{0}\" isn't a directory.".format(dirStr))
        exit(1)

    thog = truffleHog_in_dir(dirStr)
    thog.search_secrets()
    for secret in thog.detected_secrets:
        print('*'*20)
        print("Path: {0}".format(secret['path']))
        print("Reason: {0}".format(secret['reason']))
        print("Detected seccret: {0}".format(secret['detected_secret']))
        if secret['reason'] == 'High Entropy':
            print("{0}: {1}".format(secret['line_number'], secret['line_text']))

    print('')
    print("List non searched files under {0}".format(thog.scan_dir))
    for path in thog.non_searched_files:
        print("{0}: {1}".format(path['path'], path['reason']))

if __name__ == '__main__':
    if len(sys.argv) == 2:
        main()
    else:
        print("Usage: {0} <Directory>".format(sys.argv[0]))
