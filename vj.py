#!/usr/bin/env python
import json
import argparse
import os
import sys
import collections
import re

# globals
red = '\033[91m'
green = '\033[92m'
yellow = '\033[93m'
purple = '\033[94m'
pink = '\033[95m'
cyan = '\033[96m'
white = '\033[0m'
bold = '\033[1m'
underline = '\033[4m'

usage = """
Json Validator:
{}vj.py [-h] file [file ...]{}
""".format(cyan,white)


def parse_argument():
    # Parse arguments
    parser = argparse.ArgumentParser(description=usage, usage=usage, add_help=True)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('file', nargs='?', help="json file to validate")
    group.add_argument('-i', '--input', action='store_true', default=False , help='old foo help')
    args = parser.parse_args()
    return args


def check_duplicates_keys(json_text):
    result = dict()
    for key, val in json_text:
        if key in result:
            print("{}KeyError: 'Duplicate key specified: {}'{}".format(red, key, white))
            sys.exit(2)
        result[key] = val

    return result


def check_duplicates_values(json_dict):
    # t = collections.Counter([v for v in json_dict.values() if isinstance(v, basestring) or isinstance(v, int)])
    k_list = []
    # for k, v in t.iteritems():
    #     if v > 1:
    #         print("Level " + str(level) + " key " + str(k))
    #         for key in json_dict.keys():
    #             if json_dict[key] == k:
    #                 k_list.append(key)
    #         print("{}ValueError: 'Duplicate value: {} in Keys: {}'{}".format(red, v, [str(x) for x in k_list], white))
    #         sys.exit(2)
    for key, val in json_dict.iteritems():
        if type(val) == list:
            t = collections.Counter(val)
            for k, v in t.iteritems():
                if v > 1:
                    print("{}[*] ValueError: 'Duplicate value: {} in Key: {}'{}".format(red, k, key, white))
                    # sys.exit(2)
        elif type(val) == dict:
            # print(str(key) + "\t" + str(val))
            check_duplicates_values(val)


def validate(text):
    global green, white
    try:
        a = json.loads(text, object_pairs_hook=check_duplicates_keys)
        print("{}[*] No duplicate KEYS{}".format(green, white))
        check_duplicates_values(a)
        print("{}[*] No duplicate VALUES{}".format(green, white))
        return a
    except ValueError as e:
        print('{}[*] Invalid json: {}{}'.format(red, e, white))
        return None # or: raise


def validate_noerrors(text):
    global green, white
    try:
        a = json.loads(text, object_pairs_hook=check_duplicates_keys)
        print("{}[*] No duplicate KEYS{}".format(green, white))
        check_duplicates_values(a)
        print("{}[*] No duplicate VALUES{}".format(green, white))
        print("{}[*] Valid Json!{}".format(green, white))
        sys.exit(0)
    except ValueError as e:
        pass

args = parse_argument()

if args.file == None and args.input == False:
    print("{}[*] No Arguments Given! Exiting.{}".format(red, white))
elif args.file != None:
    print("[*] Checking file {}".format(args.file))
    if os.path.exists(args.file):
        with open(args.file, 'r') as jf:
            content = jf.read()

        results = validate(content)
        if results == None:
            print("{}[*] Json file {} - is not valid!{}".format(red, args.file, white))
        else:
            print("{}[*] Valid Json!{}".format(green, white))
    else:
        print("{}[*] Json file {} - Does not exists!{}".format(red, args.file, white))
elif args.input == True:
    print("please copy and paste json data below:\n"
          "To end recording Press Enter and then Ctrl+d]\n")
    lines = []
    try:
        while True:
            lines.append(raw_input())
            # content = "\n".join(lines)
            # results = validate_noerrors(content)
    except EOFError:
        pass
    content = "\n".join(lines)
    results = validate(content)
    if results == None:
        print("{}[*] Json file {} - is not valid!{}".format(red, args.file, white))
    else:
        print("{}[*] Valid Json!{}".format(green, white))