#!/usr/bin/env python

# Example use
# sudo python minesweeper.py -t https://thepiratebay.org -tm 15

import sys
import os
import json
import argparse
import util
import run
import shutil
import validators
import math
import re
import pathlib
import shutil
import urllib.parse
# import WebMinerAnalyzer

from termcolor import colored
from pymongo import MongoClient
import hashlib

'''
banner = ("""
################################################################################
################################################################################
		 _____ _         _____
		|     |_|___ ___|   __|_ _ _ ___ ___ ___ ___ ___
		| | | | |   | -_|__   | | | | -_| -_| . | -_|  _|
		|_|_|_|_|_|_|___|_____|_____|___|___|  _|___|_|
		                                    |_|
################################################################################
################################################################################
A WebMiners advanced detection tool
""").encode('utf-8')
'''
config_file = "config.json"
dir_path = os.path.dirname(os.path.realpath(__file__))
config = {"out": os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "out")}
config.update(json.load(open(config_file)))
default_time = 10
count = 0

client = MongoClient()

sites_coll = client["wasm"]["sites"]
results_coll = client["wasm"]["results"]


def hash_string(string):
    h = hashlib.new("SHA256")
    h.update(string.encode("utf-8"))
    return h.hexdigest()


def analyze_url(url, time):
    m = re.fullmatch("https?://(.+)", url)
    if not m:
        url = "http://" + url
    if not validators.url(url):
        print("The target url is malformed:", url)
        return

    if results_coll.find_one({"url": url}):
        print("Already analyzed", url)
        return
    print("URL Target: " + colored(url, 'cyan') +
          " Visiting for " + colored(str(time), 'cyan') + " sec")
    os.makedirs(config['out'], exist_ok=True)
    wasm_save_dir = pathlib.Path(config["out"])/"final"
    wasm_save_dir.mkdir(exist_ok=True)
    print("[S1] Website Analysis...")
    target = hash_string(url)
    wasm_dir = os.path.join(config['out'], target)
    cpu_stat_f = os.path.join(config['out'], target + ".txt")
    os.makedirs(wasm_dir, exist_ok=True)
    # ./chrome-build/chrome coinhive.com --no-sandbox --js-flags="--dump-wasm-module --dump-wasm-module-path=./data"
    command = config['chrome'] + ' ' + url + \
        ' --no-sandbox --headless --js-flags="--dump-wasm-module --dump-wasm-module-path=' + wasm_dir + '"'
    print(command)
    run.crawl(command, cpu_stat_f, url, time)
    wasm_files = []

    print("[S2] Looking for a wasm module...")
    for file in pathlib.Path(wasm_dir).iterdir():
        if file.name.endswith('.wasm'):
            wasm_files.append(file)
            break

    if not wasm_files:
        print("[S2] No Wasm module found... Moving to S4")
        print("[>] Hint: try to increase the timeout -tm [seconds]")
    else:
        print("\033[0;31m[*] Wasm module(s) found: {}, count: {} \033[0m".format(
            [str(item) for item in wasm_files], len(wasm_files)))
        for f in wasm_files:
            shutil.copy(f, wasm_save_dir/f.name)
    results_coll.insert_one({"url": url, "count": len(wasm_files)})
    shutil.rmtree(wasm_dir)
    os.unlink(cpu_stat_f)


if __name__ == "__main__":
    ###############################################################################
    #						Setup phase
    ###############################################################################
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        '-t', '--target', help="Targer URL to analyse", metavar=('TARGET'))
    parser.add_argument('-ws', '--wasm_analysis',
                        action='store_true', help="Only Wasm analysis")
    parser.add_argument('-mn', '--monitor', action='store_true',
                        help="Only CPU event monitor")
    parser.add_argument(
        '-tm', '--time', help="Specify the time to monitor (1-30 sec)", metavar=('TIME'), default=7)
    parser.add_argument('-f', '--file', help="url list file")
    args = parser.parse_args()
    print(args)
    # print banner
    for item in sites_coll.find():
        for url in item["urls"]:
            analyze_url(url, args.time)
    exit(0)

    target = ""
    old_t = ""
    # Check if the provided arguments are correct
    die = False
    """
    message = ""

    if args.file:
        url_list = args.file
    """

    if not args.target:
        pass
        # die = True
        # message = "No target argument provided: -t [TARGET URL]"
    else:
        target = args.target
        if "http://" not in target:
            old_t = target
            target = "http://" + target
        if not validators.url(target):
            die = True
            message = "The target url is malformed: " + args.target

    if not os.path.isfile(os.path.join(dir_path, config_file)):
        die = True
        message = "No configuration file found: " + \
            os.path.join(dir_path, config_file)

    if args.time:
        if not args.time.isdigit():
            die = True
            message = "Time specified not numeric"
        elif float(args.time) > 30 or float(args.time) < 1:
            die = True
            message = "Time specified to small or too large"

    config = util.load_from_file(os.path.join(dir_path, ""), config_file)
    if not config:
        die = True
        message = "The configuration file is malformed"

    # TODO check whether the configuration dictionary contains the right data

    if die:
        print(message)
        sys.exit()

    time = default_time
    if args.time:
        time = float(args.time)

    with open(url_list, 'r') as f:
        targets = f.readlines()

    for target in targets:
        target = target.strip()
        m = re.fullmatch("https?://(.+)", target)
        if not m:
            url = "http://" + target
        else:
            url = target
            target = m.group(1)
        if not validators.url(url):
            print("The target url is malformed:", url)
            continue

        print("URL Target: " + colored(url, 'cyan') +
              " Visiting for " + colored(str(time), 'cyan') + " sec")
    ###############################################################################
    #						Stage 1: Website analysis
    ###############################################################################
        if not os.path.exists(config['out']):
            os.makedirs(config['out'])
        print("[S1] Website Analysis...")
        wasm_dir = os.path.join(config['out'], target)
        cpu_stat_f = os.path.join(config['out'], target + ".txt")
        os.makedirs(wasm_dir, exist_ok=True)
        # ./chrome-build/chrome coinhive.com --no-sandbox --js-flags="--dump-wasm-module --dump-wasm-module-path=./data"
        command = config['chrome'] + ' ' + url + \
            ' --no-sandbox --headless --js-flags="--dump-wasm-module --dump-wasm-module-path=' + wasm_dir + '"'
        # print cpu_stat_f
        print(command)
        run.crawl(command, cpu_stat_f, url, time)

    ###############################################################################
    #						Stage 2: Wasm analysis
    ###############################################################################
        wasm_files = []

        print("[S2] Looking for a wasm module...")
        for file in pathlib.Path(wasm_dir).iterdir():
            if file.name.endswith('.wasm'):
                wasm_files.append(file)
                break

        if not wasm_files:
            print("[S2] No Wasm module found... Moving to S4")
            print("[>] Hint: try to increase the timeout -tm [seconds]")
            shutil.rmtree(wasm_dir)
            os.unlink(cpu_stat_f)
        else:
            print("\033[0;31m[*] Wasm module(s) found: {}, count: {} \033[0m".format(
                [str(item) for item in wasm_files], len(wasm_files)))
