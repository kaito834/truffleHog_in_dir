#!/usr/bin/env python
# coding: utf-8
"""
    https://github.com/dxa4481/truffleHog/
    Copyright (C) 2018 @dxa4481

    Oct. 28, 2018: @kaito834
    - Copied 4 functions below and related variables from https://github.com/dxa4481/truffleHog/
      * shannon_entropy()
      * get_strings_of_set()
      * find_entropy()
      * regex_check()
    - Modified the functions as functions in class truffleHog_in_dir

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""

import math
import os
import sys
import magic
from pathlib import Path
from chardet.universaldetector import UniversalDetector
from truffleHogRegexes.regexChecks import regexes

class truffleHog_in_dir():
    BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    HEX_CHARS = "1234567890abcdefABCDEF"
    scan_dir = ""
    detected_secrets = []
    non_searched_files = []

    def __init__(self, dir):
        self.scan_dir = dir
        self.clean()

    def clean(self):
        self.detected_secrets = []
        self.non_searched_files = []

    def shannon_entropy(self, data, iterator):
        """
        Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
        """
        if not data:
            return 0
        entropy = 0
        for x in iterator:
            p_x = float(data.count(x))/len(data)
            if p_x > 0:
                entropy += - p_x*math.log(p_x, 2)
        return entropy

    def get_strings_of_set(self, word, char_set, threshold=20):
        count = 0
        letters = ""
        strings = []
        for char in word:
            if char in char_set:
                letters += char
                count += 1
            else:
                if count > threshold:
                    strings.append(letters)
                letters = ""
                count = 0
        if count > threshold:
            strings.append(letters)
        return strings

    def find_entropy(self, filepath, contents):
        lines = contents.split("\n")
        for line_num, line in enumerate(lines, 1):
            for word in line.split():
                base64_strings = self.get_strings_of_set(word, self.BASE64_CHARS)
                hex_strings = self.get_strings_of_set(word, self.HEX_CHARS)
                for string in base64_strings:
                    b64Entropy = self.shannon_entropy(string, self.BASE64_CHARS)
                    if b64Entropy > 4.5:
                        self.detected_secrets.append({
                            'path': filepath,
                            'detected_secret': string,
                            'reason': "High Entropy",
                            'line_number': line_num,
                            'line_text': line
                            })
                for string in hex_strings:
                    hexEntropy = self.shannon_entropy(string, self.HEX_CHARS)
                    if hexEntropy > 3:
                        self.detected_secrets.append({
                            'path': filepath,
                            'detected_secret': string,
                            'reason': "High Entropy",
                            'line_number': line_num,
                            'line_text': line
                            })

    def regex_check(self, filepath, contents, custom_regexes={}):
        if custom_regexes:
            secret_regexes = custom_regexes
        else:
            secret_regexes = regexes
        regex_matches = []
        for key in secret_regexes:
            found_strings = secret_regexes[key].findall(contents)
            for found_string in found_strings:
                self.detected_secrets.append({
                    'path': filepath,
                    'detected_secret': found_string,
                    'reason': key,
                    'line_number': 'N/A',
                    'line_text': 'N/A'
                    })

    def search_secrets(self):
        dirPath = Path(self.scan_dir)

        for file in dirPath.glob("**/*"):
            # type(file): <class 'pathlib.WindowsPath'>
            # type(file.as_posix()): <class 'str'>
            if os.path.isdir(file.as_posix()):
                self.non_searched_files.append({
                    'path': file.as_posix(),
                    'reason': 'Directory'
                })
                continue

            try:
                # Detect MIME type for file
                # https://github.com/kaito834/myNotes/blob/master/snippets/python/magic_from_file.py
                # https://github.com/ahupp/python-magic#usage
                f_mimetype = magic.from_file(file.as_posix(), mime=True)
            except Exception as e:
                print("[!] Exception: {0} ({1})".format(e, type(e)))

            # Scan file to detect credentials if MIME type of the file is text/*
            if f_mimetype.split('/')[0] == 'text':
                # Detect encoding by chardet.universaldetector.UniversalDetector()
                # https://chardet.readthedocs.io/en/latest/usage.html#advanced-usage
                detector = UniversalDetector()
                with open(file, 'rb') as f:
                    for line in f.readlines():
                        detector.feed(line)
                        if detector.done:
                            break
                detector.close()

                with open(file, "r", encoding=detector.result['encoding']) as f:
                    contents = f.read()
                    self.find_entropy(file.as_posix(), contents)
                    self.regex_check(file.as_posix(), contents)
            else:
                self.non_searched_files.append({
                    'path': file.as_posix(),
                    'reason': "MIME type isn't text/*: {0}".format(f_mimetype)
                })
