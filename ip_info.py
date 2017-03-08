#!/usr/bin/env python
'''
This is a wrapper script for the nat detection query.

TODOS:
- display list of attacked hosts
- write results to a file
- save raw query results as an option
'''

# imports
import os
import argparse
import socket
import sys
from time import localtime, strftime, sleep
import csv
import mysql
import mysql.connector as MySQLdb
from collections import defaultdict
import datetime
import ast
import itertools
import curses
from multiprocessing import Process
import subprocess
try:
    from user_agents import parse
except:
    print "{}[*] Please install python user_agents package to run the script:\n{}use: 'pip install pyyaml ua-parser " \
          "user-agents'".format('\033[91m', '\033[96m')
    sys.exit(1)
try:
    import dateparser
except:
    print "{}[*] Please install python dateparser package to run the script:\n{}use: 'pip install dateparser'".format(
        '\033[91m','\033[96m')
    sys.exit(1)

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

date_time = strftime("%d%m%y-%H_%M_%S", localtime())
client_query_success = 0
ato_query_success = 0
nat_query_success = 0

logdir = "{}/{}/".format(date_time,'queries')
querydir = "{}/{}/".format(date_time,'queries')
sub_directories = [logdir, querydir] # list of sub directories to create
query_file = '{}nat_detect_query_{}.hql'.format(querydir, date_time)
query_results = query_file+".out"
parsed_result_file = '{}nat_detection_results_{}.txt'.format(querydir, date_time)


# DB
db = ''
db_cursor = 'default'
DB_NAME = 'NAT_DETECT'
DB_USER = 'root'
DB_PASS = 'rkraRh6w'

CONFIG = {
    'user': DB_USER,
    'password': DB_PASS,
    'host': '127.0.0.1',
    'database': DB_NAME,
    'raise_on_warnings': False,
    'use_pure': False,
    'autocommit': True,
}


usage = r"""{}

 ______   ____        ______             ___
/\__  _\ /\  _`\     /\__  _\          /'___\
\/_/\ \/ \ \ \L\ \   \/_/\ \/     ___ /\ \__/  ___
   \ \ \  \ \ ,__/      \ \ \   /' _ `\ \ ,__\/ __`\
    \_\ \__\ \ \/        \_\ \__/\ \/\ \ \ \_/\ \L\ \
    /\_____\\ \_\        /\_____\ \_\ \_\ \_\\ \____/
    \/_____/ \/_/        \/_____/\/_/\/_/\/_/ \/___/


{}Author: Elad Shuster
[*] AKAMAI - Threat Research [*]

{}usage:   {}nat_detect.py  [-c DAYS_AGO] [-db] [-t date,time,increment,unit] [-dh] [-g] [-p] [PRIORITY]
         [-dc] [DATACENTER] ip[s]
{}example: {}nat_detect.py -c 10 -db -t thursday,09:00,1,d -p very_high -dc sj 1.1.1.1, 2.2.2.2-2.2.2.50, 3.3.3.0/24

{}positional arguments:{}
  {}ip[s]                                         {}ip, list of ips, range or ips, cidr

{}optional arguments:{}
  {}-c, --clientintl [DAYS_AGO]                   {}use client_intl where ts >= [DAYS_AGO] to retrieve information about
                                                attacked accounts, host and heuristic timestamps
  {}-h, --help                                    {}show this help message and exit
  {}-db, --database                               {}insert results to Mysql DB
  {}-dc [DATACENTER], --datacenter [DATACENTER]   {}specify data center (default = 'virginia')
  {}-dh, --hosts                                  {}Displat a list of hosts attacked by the IP[s]
  {}-g, --gather                                  {}gather evidence from evidence_properties based on attack
                                                timestamps in client_intl
  {}-p [PRIORITY], --priority [PRIORITY]          {}specify query priority (default = 'very_high')
  {}-t, --time (initial date, initial time, increment, increment unit)
                                                {}specify ddc timestamp[s] -
                                                  {}full syntax examples:{}
                                                    10/10/2016,00:00,1,d - one day starting at 10/10/2016 00:00 GMT+
                                                    02/03/2016,09:00,3,h - 3 hours starting at 02/03/2016 GMT+
                                                    friday,17:00,3,d - 3 days starting at last friday 17:00
                                                    yesterday,09:00,5,h - 5 hours starting at yesterday 09:00
                                                  {}initial time examples:{}
                                                    'thursday' - parsed as last X day
                                                    'X_days_ago', '2_weeks_ago', '30/10/2016'
                                                  {}increment units:{} d (days) or h (hours)

  {}-d, --debug                                   {}Run Script in DEBUG mode

            {}""".format(green, pink, yellow, cyan, yellow, cyan, white, cyan, yellow, pink, white, pink, yellow,
                         pink, yellow, pink, yellow, pink, yellow, pink, yellow, pink, yellow, pink, yellow, pink,
                         yellow, pink, yellow, pink, cyan, green, cyan, green, cyan, green, yellow, pink, yellow)

def parse_argument():
    # Parse arguments
    parser = argparse.ArgumentParser(description=usage, usage=usage, add_help=True)
    parser.add_argument('ips', nargs='+', help="ip or list of ips")
    parser.add_argument('-c', '--clientintl_daysago', action='store', metavar='DAYS_AGO', default=argparse.SUPPRESS,
                        nargs='?', type=int, help="use client_intl where ts >= [DAYS_AGO] to retrieve information "
                                                  "about "
                                        "attacked accounts, host and heuristic timestamps")
    parser.add_argument('-db', '--database', action='store_true', default=False , help="insert Results to Mysql DB")
    parser.add_argument('-dc', '--datacenter', action='store', default='virginia', nargs='?', help="specify data "
                                                                                                   "center")
    parser.add_argument('-dh', '--hosts', action='store_true', default=False, help="Display a list of hosts attacked "
                                                                                   "by the IP[s]")
    parser.add_argument('-g', '--gather', action='store_true', default=False, help="gather evidence from "
                                                                                   "evidence_properties based on "
                                                                                   "attack timestamps in client_intl")
    parser.add_argument('-p', '--priority', action='store', default='very_high', nargs='?', help="specify query "
                                                                                                "priority")
    parser.add_argument('-q', '--quiet', action='store_true', default=True, help="quiet mode - suppress run_query's "
                                                                                  "screen output")
    parser.add_argument('-t', '--time', action='store', default=argparse.SUPPRESS, nargs='+', help="specify date[s] "
                                                                                                   "to search in ddc data")
    parser.add_argument('-d', '--debug', action='store_true', default=False , help="Run Script in DEBUG mode")
    args = parser.parse_args()
    if args.debug:
        print "ARGS:" + str(args)

    return args

def parse_ua(user_agent):
    ua = parse(user_agent)
    os_family = ua.os.family
    device = ua.device.family
    browser_family = ua.browser.family
    browser_version = ua.browser.version_string

    results = [os_family, device, browser_family, browser_version]
    return results


def write_row(file, row):
    with open(file, 'ab+') as csvfile:
        csvwriter = csv.writer(csvfile, delimiter='\t', doublequote=False, quoting=csv.QUOTE_ALL,
                                  quotechar='"', escapechar='\\', lineterminator='\n')
        csvwriter.writerow(row)

def os_run_query(command):
    os.system(command)

def run_query (query, tag, timestamp, args, date_time):

    # Initialize query files
    query_file = '{}{}_query_{}.hql'.format('{}/{}/'.format(date_time,'queries'),tag,timestamp)
    result_file = '{}.out'.format(query_file)
    log_file = '{}{}_query_{}.hql.log'.format('{}/{}/'.format(date_time,'logs'),tag, timestamp)

    # write query to file
    with open(query_file, 'w') as q:
        q.write(query)

    if args.quiet == True:
        ###quiet = '&> {}'.format(log_file)
        quiet = ''
    else:
        quiet = ''

    # run query
    #print "Tag: {}".format(tag)
    #print "{}[*] Running Query:\n{}{}{}".format(yellow, purple, query, cyan)
    command = 'run_query.py -l -p {} {} {} {}'.format(args.priority, query_file, args.datacenter, quiet)
    #print "[*] {}".format(command)


    os.system(command)

    # check if query was successful
    if os.path.exists(result_file):
        content = []
        temp_content = []

        # reading query result file
        with open(result_file, 'r') as res:
            temp_content = res.readlines()

        # remove unnecessary lines added by hive on san-jose dc
        for line in temp_content:
            if line.find('Unable to load native-hadoop library for your platform...') == -1 and \
               line.find('WARN: The method class org.apache.commons.logging.impl.SLF4JLogFactory#release() was '
                         'invoked.') == -1 and line.find(
                'WARN: Please see http://www.slf4j.org/codes.html#release for an explanation.') == -1:
                content.append(line)
    else:
        print "{}[*] Query Failed!\n{}\n\nPlease Check the log file for more details:\n{}{}".format(red, query,
                                                                                                    log_file,white)
        content = []
        with open(result_file, 'w') as result:
            for line in content:
                result.write(line)
        return

    if not args.debug:
        try:
            #os.system("rm {} {}".format(query_file, result_file))
            #print "{}[*] Removing query files...{}".format(yellow, white)
            pass
        except:
            print "{}[*] Error Deleting Query Files{}".format(red, white)
    print "{}[*] Query Ended Successfully!".format(green)

    with open(result_file, 'w') as result:
        for line in content:
            result.write(line)
    return


def read_file_lines(file):
    with open(file, 'r') as f:
        content = f.readlines()
    return content

def read_query_results(file):
    content = []
    temp_content = []

    # reading query result file
    with open(file, 'r') as res:
        temp_content = res.readlines()

    # remove unnecessary lines added by hive on san-jose dc
    for line in temp_content:
        if line.find('Unable to load native-hadoop library for your platform...') == -1 and \
                        line.find(
                            'WARN: The method class org.apache.commons.logging.impl.SLF4JLogFactory#release() was '
                            'invoked.') == -1 and line.find(
            'WARN: Please see http://www.slf4j.org/codes.html#release for an explanation.') == -1 and line != '':
            content.append(line)

    return content


def get_last_log_line(log_file):
    command = "tail -n 1 {}".format(log_file)
    proc = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    return out.replace("\n","")


def check_processes(process_list):
    '''
    This function takes a list of processes and return True if one of them is still running (alive)
    :param process_list:
    :return: True / False
    '''
    live_process_counter = 0
    for process in process_list:
        if process.is_alive():
            live_process_counter += 1

    if live_process_counter == 0:
        return False
    else:
        return True


############### Main ################
args = parse_argument()


############### Argument Processing and Other Validations ######################

# check if quiet mode was enables
if args.quiet == True:
    quiet = '> /dev/null'
else:
    quiet = ''

if args.datacenter not in ('sj', 'virginia'):
    print "{}[*] ERROR - Invalid DC Chosen!".format(red)
    sys.exit(1)

banner = r"""{}

          `/ossss/` `:ossssssssssssssssssssso/.
         :ossss+. ./sssssso+/:-..````...-:/+oss+.
       `+sssss:``:ossss+:.`    ``````       ``-/+-                _ _|   _ \      _ _|          _|
      `osssss- `+ssso:`  `-:++ooosssooo+/:.`    `.                  |   |   |       |   __ \   |     _ \
     `osssss- `osso-` .-///::------::/++osso/-`                     |   ___/        |   |   |  __|  (   |
     ssssss/  +ss/`   .``               ``-:+o+:`                 ___| _|         ___| _|  _| _|   \___/
    -ssssso` -so-                            `.:/.
    +sssss/  +o.                                 `
   `osssss- `o-
   .ssssss. `+`                  `:::::::::`       -::::`                                                                     `-::::`
   .ssssss.  :                  `://///////.      .////:                                                                      ./:::-
   `osssss-  .                 `:////::////-      :////.                                                                      ``````
    +sssss/  .                `:////:`:////:     `////:`  `.....`  ``..----...`   `....```.--..`  `..-..`     `...----...`   `.....
    .ssssso.                 `:////:` -////:`    -////-  -:///:`  -:///:::////:.  -////:://////:.:///////-  `-:///:::////:`  -////.
     /sssss+                `:////:`  -/////`    :///:``:///:.   .::::-```-////: `/////-..-/////:-..:////:  -::::.```:////. `:///:
     `+sssss/              `:////:`   ./////.   .////:-:///-`    ``......`-////. .////-   `////:`   -////-  `......``:////` -////-
      `+sssss:            `://///:----://///-   ://///////:     .::///:::::///:` :///:`   .////-   `:///:` -:///:::::////:  :////`
        /sssss/`         `://///////////////:  `////:`:////-   .////-````:////- .////-    :////`   .////- -////-````:////. .////-
         -+sssso-`      `:////:........:////:` -////. `:////-  :////-```.:////` :////.   .////:    :////``/////-``.-////:  :////.
          `:ossss+-    `:////:`        :////:``:///:`  .////:. -://///::-////- `:///:    -////.   `////:  ::////::::////- `////:
            `-+osss+-` `.....`         `..... `....`    `....`  `.....```....` `....`    `...`    `....`   `.....` `....` `....`
               `:+osso/-`

{}Author: Elad Shuster
""".format(cyan,pink)

banner1 = r"""{}
 ______   ____                                  ___
/\__  _\ /\  _`\          __                  /'___\
\/_/\ \/ \ \ \_\ \       /\_\        ___     /\ \__/       ___
   \ \ \  \ \ ,__/       \/\ \     /' _ `\   \ \ ,__\     / __`\
    \_\ \__\ \ \/         \ \ \    /\ \/\ \   \ \ \_/    /\ \_\ \
    /\_____\\ \_\          \ \_\   \ \_\ \_\   \ \_\     \ \____/
    \/_____/ \/_/           \/_/    \/_/\/_/    \/_/      \/___/



{}Author: Elad Shuster
""".format(cyan,pink)


print "{}{}{}".format(cyan, banner, white)
ips = []
# get list of ips and strip all quotation marks
for arg in args.ips:
    ip = arg.replace("'",'').replace('"','').replace('[','').replace(']','').replace('(','').replace(')','').replace(
        ",",'')
    ip = str(ip)
    # Check if ip is a cidr (10.0.0.0/24) or a range (10.0.0.1-10.0.0.40)
    if ip.find("/") != -1 or ip.find("-") != -1 or ip.find('\xe2') != -1:
        try:
            import netaddr
        except:
            print "{}[*] Please install python netaddr package to run the script:\n{}use: pip install netaddr".format(
                red, cyan)
            sys.exit(1)
        try:
            if ip.find("/") != -1:
                cidr = netaddr.IPNetwork(ip)
                for addr in cidr:
                    ips.append(str(addr))
            elif ip.find("-") != -1 or ip.find('\xe2') != -1:
                if ip == "-":
                    print "{}[*] ERROR - Please remove spaces from IP Range! (1.1.1.1-1.1.1.7) instead of (1.1.1.1 - " \
                          "1.1.1.7)" \
                          "{}".format(red,white)
                    sys.exit(1)
                if ip.find("-") != -1:
                    ip_range = netaddr.IPRange(ip.split("-")[0],ip.split("-")[1])
                for addr in ip_range:
                    ips.append(str(addr))
        except:
            print "{}[*] ERROR - Error Parsing ip / ip range - {} in {}{}.".format(red,ip, args.ips, white)
            print "{}[*] If the IP / IP Range was pasted from JIRA or other Web Page - Please Type Them " \
                  "Manually! ".format(red, white)
            raise()
    else:
        ips.append(ip)

# validate ips
for ip in ips:
    if ip.find(":") == -1:
        try:
            socket.inet_aton(ip)
            # legal
            print "{}[*] IP {} is a Valid IP Address!".format(green, ip)
        except socket.error:
            # Not legal
            print "{}[*] IP address {} is no valid".format(red,ip)
            sys.exit(1)

query_ips = '' # list of ips for query
for ip in ips:
    query_ips += "'{}', ".format(ip)

# remove final ", " from list
query_ips = query_ips[:-2]


# validate time input


time_error_msg = """
        {0} Correct syntax:
            -t, --time (initial date, initial time, increment, increment unit)
           {1}full syntax examples:{2}
             10/10/2016,00:00,1,d - one day starting at 10/10/2016 00:00 GMT+
             02/03/2016,09:00,3,h - 3 hours starting at 02/03/2016 GMT+
             friday,09:00,3,d - 3 days starting at last friday 09:00
             yesterday,09:00,5,h - 5 hours starting at yesterday 09:00
            {1}initial time examples:{2}
              'thursday' - parsed as last X day
              'X_days_ago', '2_weeks_ago', '31/12/2015'
            {1}increment units:{2} d (days) or h (hours){3}
        """.format(yellow, pink, green, white)

if 'time' in args:
    input_list = args.time[0].strip("(").strip(")").split(",")
    if len(input_list) != 4:
        print "{}ERROR! Malformed ddc time parameter: {}".format(red, args.time)
        print time_error_msg
        sys.exit(1)
    else:
        initial_datetime = "{} {}".format(input_list[0],input_list[1])
        if initial_datetime.find('last ') != -1:
            # no need for the 'last' keyword - day name is parsed as last xday without using the string last before
            parsed_time = dateparser.parse(initial_datetime.replace('last ', ''))
        elif initial_datetime.find('@') != -1 or initial_datetime.find('_') != -1:
            # for those using run_query's notation of '@day_ago'
            parsed_time = dateparser.parse(initial_datetime.replace('@', '').replace('_', ' '))
        else:
            parsed_time = dateparser.parse(initial_datetime)
        if type(parsed_time) != datetime.datetime:
            # time parsing failed
            print "{}ERROR! Malformed ddc time parameter: {}".format(red, args.time)
            print time_error_msg
            sys.exit(1)
        else:
            # parsing was successful
            query_start_time = datetime.datetime(parsed_time.year, parsed_time.month, parsed_time.day,
                                                 parsed_time.hour, 0).strftime('%s')
            query_start_time_for_display = datetime.datetime(parsed_time.year, parsed_time.month, parsed_time.day,
                                                 parsed_time.hour, 0).strftime("%a, %d %b %Y %H:%M:%S +0000")
            #print "{}[*] NAT Query Start Time: {}{}".format(yellow, cyan, query_start_time_for_display)
            if input_list[3] == 'h':
                # increment hours to end date (besides GMT offset)
                query_end_time = datetime.datetime(parsed_time.year, parsed_time.month, parsed_time.day,
                                        parsed_time.hour + int(input_list[2]), 0)
            elif input_list[3] == 'd':
                # increment days to start date
                query_end_time = datetime.datetime(parsed_time.year, parsed_time.month, parsed_time.day +
                                                   int(input_list[2]), parsed_time.hour, 0)
            else:
                print "{}ERROR! Malformed ddc time parameter: {}".format(red, args.time)
                print time_error_msg
                sys.exit(1)
            #print "{}[*] NAT Query End Time: {}{}".format(yellow, cyan, query_end_time.strftime("%a, %d %b %Y %H:%M:%S +0000"))
            query_end_time_for_display = query_end_time.strftime("%a, %d %b %Y %H:%M:%S +0000")
            # converting to epoch milliseconds to use in query syntax
            query_end_time = query_end_time.strftime('%s')
    nat_query_ts = "(ts>='{}' and ts<'{}')".format(int(query_start_time)*1000, int(query_end_time)*1000)
    #print nat_query_ts
else:
    nat_query_ts = "ts>='@day_ago' AND ts<'@now'"


####### Create Subdirectories ##########

for directory in sub_directories:
    if not os.path.exists(directory):
        os.makedirs(directory)


####### Launch Queries Based On Given Arguments #######

### Stage 0 queries
# NAT QUERY - Always Runs
# ATO QUERY - Always Runs
# Client_intl QUERY - Depands on given arguments

### Stage 1 queries - queries that depand on the results of client_intl run
# Attacked accounts QUERY - Depands on client_intl query results
# Evidence_properties - Depands on timestamps extracted form client_intl results


# Running Stage 0 Queries
sub_queries_flag = 0 # this flag is used to mark the first while loop in which the script identifies that client_intl
process_list = [] # list of spawned processes

#  query is done and can now start stage 1 queries

query = """
SELECT
    t1.ip as ip,
    t2.ACCOUNTNAME AS account_name,
    t3.SUBVERTICAL AS subvertical,
    t1.UA AS ua,
    t1.TOTAL AS total,
    t1.company as company,
    t1.country as country,
    t1.domain as domain,
    t1.network_type as network_type,
    t1.asnum as asnum
   FROM
     (SELECT b2s(ip) as ip,
             getED(ip, 'company') as company,
             getED(ip, 'country') as country,
             getED(ip, 'domain') as domain,
             getED(ip, 'network_type') as network_type,
             getED(ip, 'asnum') as asnum,
             cpcode AS CPCODE,
             user_agent AS UA,
             sum(total_counter) AS TOTAL
      FROM ddc_nat
      WHERE b2s(ip) in ({0})
        AND {1}
      GROUP BY b2s(ip), getED(ip, 'company'),
               getED(ip, 'country'),
               getED(ip, 'domain'),
               getED(ip, 'network_type'),
               getED(ip, 'asnum'), Cpcode,
               user_agent) t1
   LEFT OUTER JOIN
     (SELECT DISTINCT cpcode AS CPCODE,
                      account_name AS ACCOUNTNAME,
                      account AS ACCOUNTID
      FROM cpcode_metadata
      WHERE {1}
      AND lower(account_name) not rlike ('marketo|bazaarvoice|vungle')) t2 ON (t1.CPCODE = t2.CPCODE)
   LEFT OUTER JOIN
     (SELECT DISTINCT account_id AS ACCOUNTID,
                      vertical AS VERTICAL,
                      subvertical AS SUBVERTICAL
      FROM account_industries
      WHERE {1}) t3 ON (t2.ACCOUNTID = t3.ACCOUNTID)
   WHERE (t3.SUBVERTICAL IN ('Logistics',
                             'Advertising Technology',
                             'Enterprise Software (B2B)',
                             'Enterprise Hardware',
                             'Asset Management',
                             'Business Services',
                             'BPO',
                             'Information Services',
                             'Security Software')
          OR t3.VERTICAL IN ('Software as a Service','Business Services'))
    ORDER BY ip
""".format(query_ips, nat_query_ts)



if args.debug:
    nat_query_content = read_file_lines('nat_query')
else:
    # start the NAT Query
    timestamp = strftime("%d%m%y-%H%M%S", localtime())
    t_nat = Process(target=run_query, args=(query, 'nat', timestamp, args, date_time))
    nat_log = '{}{}_query_{}.hql.log'.format(logdir,'nat', timestamp)
    nat_result_file = '{}{}_query_{}.hql.out'.format(querydir, 'nat', timestamp)
    process_list.append(t_nat)
    t_nat.start()
    sleep(4)

ato_query="""
SELECT
    ip,
    count(distinct host) AS count_hosts,
    count(distinct email_hash) as count_emails,
    collect_set(distinct host) as host_collection
FROM
    ato
WHERE
    ip IN ({})
    AND {}
GROUP BY
    ip;
""".format(query_ips,nat_query_ts)


if args.debug:
    try:
        ato_query_content = read_file_lines('ato_query')
    except:
        print 'ATO Result File Not Found!'
        ato_query_content = ['']
else:
    # start the ATO Query
    timestamp = strftime("%d%m%y-%H%M%S", localtime())
    t_ato = Process(target=run_query, args=(ato_query, 'ato', timestamp, args, date_time))
    ato_log = '{}{}_query_{}.hql.log'.format(logdir, 'ato', timestamp)
    ato_result_file = '{}{}_query_{}.hql.out'.format(querydir, 'ato', timestamp)
    process_list.append(t_ato)
    t_ato.start()
    sleep(4)

if 'clientintl_daysago' in args:

    # get client intel data

    ts = "ts>='@{}_days_ago' AND ts<'@now'".format(args.clientintl_daysago)
    clientintl_query = """
    SELECT *
    FROM client_intl
    WHERE
        ip IN ({})
        AND {}
        AND isnotnull(heuristic_detected)
    ORDER BY ts;
    """.format(query_ips,ts)


    if args.debug:
        clientintl_content = read_file_lines('client_intel')
    else:
        # start the client_intel Query
        timestamp = strftime("%d%m%y-%H%M%S", localtime())
        t_client_intel = Process(target=run_query, args=(clientintl_query, 'client_intel', timestamp, args, date_time))
        clientintl_log = '{}{}_query_{}.hql.log'.format(logdir, 'client_intel', timestamp, args)
        clientintl_result_file = '{}{}_query_{}.hql.out'.format(querydir, 'client_intel', timestamp)
        process_list.append(t_client_intel)
        t_client_intel.start()
        sleep(2)

        # initial test to check if threads are running
        ###thread_test = t_nat.is_alive() or t_ato.is_alive() or t_client_intel.is_alive() # debug
        ###thread_test = check_processes(process_list)
###elif not args.debug:
    # if client intel was not chosen, trying to check if t_client_intel is alive would result in an error
    ###thread_test = t_nat.is_alive() or t_ato.is_alive()
    ###thread_test = check_processes(process_list)

if not args.debug:
    # no need to run the queries in debug mode
    try:
        stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        curses.start_color()
        curses.init_pair(1, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLACK)
        thread_test = check_processes(process_list)
        while thread_test:

            for c in itertools.cycle(['|', '/', '-', '\\']):
                stdscr.clear()
                if t_nat.is_alive():
                    # if process is alive and result file already exists - kill the process - query  has ended
                    if os.path.exists(nat_result_file):
                        t_nat.terminate()
                    if os.path.exists(nat_log):
                        line = get_last_log_line(nat_log)
                        nat_c = 1
                    else:
                        line = 'NAT Query - Initializing Query....'
                        # choose line ouptut color
                        nat_c = 3
                    nat_line = '{0} NAT Query Running {0} - {1} - {2}'.format(c, nat_log, line)

                else:
                    nat_line = "[*] NAT Query Ended!"
                    # choose line ouptut color
                    nat_c = 2
                if t_ato.is_alive():
                    # if process is alive and result file already exists - kill the process - query  has ended
                    if os.path.exists(ato_result_file):
                        t_ato.terminate()
                    if os.path.exists(ato_log):
                        line = get_last_log_line(ato_log)
                        ato_c = 1
                    else:
                        line = 'ATO Query - Initializing Query....'
                        # choose line ouptut color
                        ato_c = 3
                    ato_line = '{0} ATO Query Running {0} - {1} - {2}'.format(c, ato_log, line)
                else:
                    ato_line = "[*] ATO Query Ended!"
                    # choose line ouptut color
                    ato_c = 2

                # test queries before looping
                if 'clientintl_daysago' in args:
                    acc_c = 3
                    evidence_c = 3
                    if t_client_intel.is_alive():
                        # if process is alive and result file already exists - kill the process - query  has ended
                        if os.path.exists(clientintl_result_file):
                            t_client_intel.terminate()
                        if os.path.exists(clientintl_log):
                            line = get_last_log_line(clientintl_log)
                            client_c = 1
                        else:
                            line = 'Client Intel Query - Initializing Query....'
                            # choose line ouptut color
                            client_c = 3
                        client_line = '{0} Client Intel Query Running {0} - {1} - {2}'.format(c,
                                                                                                 clientintl_log,
                                                                                                 line)
                        accounts_line = '[!] Attacked Accounts Query - Waiting For Client Intel Results As Input ...'
                        evidence_line = '[!] Evidence Properties Query - Waiting For Client Intel Results As Input ...'
                    else:
                        client_line = "[*] Client Intel Query Ended Successfully!"
                        # choose line ouptut color
                        client_c = 2
                        # incrase sub query count - idicates that client intl is over and the script can now launch
                        # sub queries
                        sub_queries_flag +=1
                        # launching other queries - processes for these queries should be spawned only once - thus the
                        # counter
                        if sub_queries_flag == 1:
                            #### Verify client_intl query results and start Stage 1 Queries ####
                            # if queries ended, stage 1 queries can start

                            # test if client_intl flag was specified - Redundant check can be removed
                            if 'clientintl_daysago' in args:
                                client_intl_acc_list = []
                                client_intl_host_list = []
                                clientintl_content = read_query_results(clientintl_result_file)
                                if len(clientintl_content) == 1:
                                    print "{}[*] client_intl Query Returned No Results!{}".format(red, white)
                                    client_line = "[*] client_intl Query Returned No Results!"
                                    # choose line ouptut color
                                    client_c = 3
                                    client_query_success = 0
                                elif len(clientintl_content) == 0:
                                    print "{}[*] client_intl Query Failed!{}".format(red, white)
                                    client_line = "[*] client_intl Query Failed!"
                                    # choose line ouptut color
                                    client_c = 3
                                    client_query_success = 0
                                else:
                                    client_query_success = 1
                                    client_intl_heur_timestamps = []
                                    heuristic_hosts = defaultdict(list)  # dictionary of hosts per heuristic
                                    account_heuristics = defaultdict(list)  # dictionary of heuristics per account
                                    attack_categories_list = []
                                    for line in clientintl_content[1:]:  # ignore header line
                                        # parse the results of client_intl query and extract attack timestamps and
                                        # attacked accounts for use in stage 1 queries
                                        client_intl_data = line.strip('\n').split(
                                            '\t')  # split TAB delimited data to columns

                                        if client_intl_data[3].lower() == 'false':
                                            pass
                                        else:
                                            ts = int(client_intl_data[0])
                                            parsed_ts = datetime.datetime.fromtimestamp(int(ts) / 1000)
                                            rounded_ts = int(datetime.datetime(parsed_ts.year, parsed_ts.month, parsed_ts.day,
                                                                               parsed_ts.hour, 0).strftime('%s'))*1000

                                            if rounded_ts not in client_intl_heur_timestamps:
                                                client_intl_heur_timestamps.append(rounded_ts)

                                            # parse the evidences field in client_intl
                                            client_intl_heur_dict = ast.literal_eval(client_intl_data[9])
                                            client_intl_heur_dict = client_intl_heur_dict[0]

                                            heuristic_name = client_intl_heur_dict['heuristic_name'][
                                                             :client_intl_heur_dict['heuristic_name'].find(";")]

                                            if client_intl_heur_dict['category'] not in attack_categories_list:
                                                attack_categories_list.append(client_intl_heur_dict['category'])

                                            # add unique hosts for each heuristic
                                            for host in client_intl_heur_dict['hosts']:
                                                if host not in heuristic_hosts[heuristic_name]:
                                                    heuristic_hosts[heuristic_name].append(host)

                                            # add hosts to unique list of hosts
                                            line_hosts = client_intl_data[07][1:-1].split(",")
                                            for host in line_hosts:
                                                if host not in client_intl_host_list and host != '':
                                                    client_intl_host_list.append(host)

                                            # add accounts to unique list of accounts
                                            line_accounts = client_intl_data[05][1:-1].split(",")
                                            for acc in line_accounts:
                                                if acc not in client_intl_acc_list and acc != '':
                                                    client_intl_acc_list.append(acc)

                                                # add heuristics triggered per account
                                                if heuristic_name not in account_heuristics[acc]:
                                                    account_heuristics[acc].append(heuristic_name)
                                    # client intel query results have been parsed, start stage 1 queries

                                    # query attacked accounts
                                    if args.debug:
                                        accounts_query_results = read_file_lines('accounts_query')
                                    else:
                                        if client_intl_acc_list != []:
                                            # get attacked accounts names
                                            query_account_list = ''
                                            for acc in client_intl_acc_list:
                                                query_account_list += "'{}', ".format(acc.strip("'").strip('"'))
                                            query_account_list = query_account_list[:-2]
                                            accounts_query = """
                                            SELECT DISTINCT cpcode AS CPCODE,
                                                            account_name AS ACCOUNTNAME,
                                                            account AS ACCOUNTID
                                            FROM cpcode_metadata
                                            WHERE account in ({});""".format(query_account_list)

                                            # start the client_intel Query
                                            timestamp = strftime("%d%m%y-%H%M%S", localtime())
                                            t_accounts = Process(target=run_query, args=(accounts_query, 'accounts',
                                                                                         timestamp, args, date_time))
                                            accounts_log = '{}{}_query_{}.hql.log'.format(logdir, 'accounts', timestamp)
                                            accounts_result_file = '{}{}_query_{}.hql.out'.format(querydir, 'accounts',
                                                                                                timestamp)
                                            process_list.append(t_accounts)
                                            t_accounts.start()
                                            sleep(3)
                                        else:
                                            # defining log file name so that the next elif can check if the query ran
                                            # and the log file was created
                                            timestamp = strftime("%d%m%y-%H%M%S", localtime())
                                            accounts_log = '{}{}_query_{}.hql.log'.format(logdir, 'accounts', timestamp)

                                    # query evidence_properties
                                    if args.debug and args.gather:
                                        evidence_query_results = read_file_lines('evidence_query')
                                    elif not args.gather:
                                        evidence_line = '[*] Evidence Properties Query - Flag (-g) Not ' \
                                                        'Enabled.'
                                        # choose line ouptut color
                                        evidence_c = 3
                                    elif args.gather:
                                        # verify that heuristic timestamps were found
                                        if client_intl_heur_timestamps != []:
                                            # get heuristic timestamps
                                            evidence_ts_list = ''
                                            for ts in client_intl_heur_timestamps:
                                                evidence_ts_list += "{}, ".format(str(ts).strip("'").strip('"'))
                                            evidence_ts_list = evidence_ts_list[:-2]
                                            evidence_query = """
SELECT intermediate_data.client_id AS IP,
       getED(intermediate_data.client_id,'company') AS COMPANY,
       getED(intermediate_data.client_id,'domain') AS DOMAIN,
       intermediate_data.heuristic_name AS HEURISTIC_NAME,
       intermediate_data.score AS SCORE,
       evidence_properties.key AS KEY ,
       evidence_properties.value AS VALUE,
       innerTable.HOSTS AS HOSTS,
       intermediate_data.ts AS TS
FROM intermediate_data
JOIN evidence_properties ON (intermediate_data.id = evidence_properties.id
                             AND intermediate_data.ts = evidence_properties.ts)
LEFT JOIN
  (SELECT host_stats.ts AS TS,
          host_stats.id ID,
          collect_set(host_stats.host) AS HOSTS
   FROM host_stats
   WHERE ts in ({0})
   GROUP BY host_stats.id,
            host_stats.ts) innerTable ON (intermediate_data.id = innerTable.ID
                                          AND intermediate_data.ts = innerTable.TS)
WHERE intermediate_data.client_id IN ({1})
  AND intermediate_data.ts in ({0})
  AND evidence_properties.ts in ({0})
  AND intermediate_data.heuristic_name NOT LIKE '%Score%'
  AND intermediate_data.group_ids LIKE '%production%'
                                            """.format(evidence_ts_list, query_ips )

                                            # start the evidence Query
                                            timestamp = strftime("%d%m%y-%H%M%S", localtime())
                                            t_evidence = Process(target=run_query,
                                                args=(evidence_query, 'evidence', timestamp, args, date_time))
                                            evidence_log = '{}{}_query_{}.hql.log'.format(logdir, 'evidence', timestamp,
                                                                                      args)
                                            evidence_result_file = '{}{}_query_{}.hql.out'.format(querydir, 'evidence',
                                                                                                timestamp)
                                            process_list.append(t_evidence)
                                            sleep(5)
                                            t_evidence.start()
                                        else:
                                            # defining log file name so that the next elif can check if the
                                            # query ran and the log file was created
                                            timestamp = strftime("%d%m%y-%H%M%S", localtime())
                                            evidence_log = '{}{}_query_{}.hql.log'.format(logdir, 'evidence', timestamp)


                            # test to check if threads are running
                            ### thread_test = t_nat.is_alive() or t_ato.is_alive() or t_client_intel.is_alive()
                            ###thread_test = check_processes(process_list)
                        elif sub_queries_flag > 1 and client_query_success == 1:
                            # sub queries >1 - means subqueries has been launched already - no need to run through
                            # the launch sequence again
                            if os.path.exists(accounts_log):
                                if t_accounts.is_alive():
                                    # if process is alive and result file already exists - kill the process - query  has ended
                                    if os.path.exists(accounts_result_file):
                                        t_accounts.terminate()
                                    else:
                                        line = get_last_log_line(accounts_log)
                                        acc_c = 1
                                        accounts_line = '{0} Accounts Query Running {0} - {1} - {2}'.format(c, accounts_log, line)
                                else:
                                    accounts_line = "[*] Attacked Accounts Query Ended!"
                                    # choose line ouptut color
                                    acc_c = 2
                            else:
                                accounts_line = '{0} Attacked Accounts {0} - Initializing Query....'.format(c)
                                # choose line ouptut color
                                acc_c = 3

                            if args.gather:
                                if os.path.exists(evidence_log):
                                    if t_evidence.is_alive():

                                        # if process is alive and result file already exists - kill the process -
                                        #  query  has ended
                                        if os.path.exists(evidence_result_file):
                                            t_evidence.terminate()
                                        else:
                                            # get query progress from query log file
                                            line = get_last_log_line(evidence_log)
                                            evidence_c = 1
                                            evidence_line = '{0} Evidence Properties Query Running {0} - {1} - {' \
                                                            '2}'.format(c, accounts_log, line)
                                    else:
                                        evidence_line = "[*] Evidence Properties Query Ended!"
                                        # choose line ouptut color
                                        evidence_c = 2
                                else:
                                    evidence_line = '{0} Evidence Properties Query {0} - Initializing ....'.format(c)
                                    # choose line ouptut color
                                    evidence_c = 3
                            else:
                                evidence_line = '[*] Evidence Properties Query - Flag (-g) Not Enabled.'
                                # choose line ouptut color
                                evidence_c = 3

                        elif client_query_success == 0:
                            if len(clientintl_content) == 1:
                                accounts_line = "[*] Attacked Accounts Query Could Not Initialize - Client Intel " \
                                                "Query Returned No Results!"
                                # choose line ouptut color
                                acc_c = 3
                                evidence_line = "[*] Evidence Properties Query Could Not Initialize - Client Intel " \
                                                "Query Retuned No Results!"
                                # choose line ouptut color
                                evidence_c = 3
                            else:
                                accounts_line = "[*] Attacked Accounts Query Could Not Initialize - Client Intel " \
                                                "Query Failed!"
                                # choose line ouptut color
                                acc_c = 3
                                evidence_line = "[*] Evidence Properties Query Could Not Initialize - Client Intel " \
                                                "Query Failed!"
                                # choose line ouptut color
                                evidence_c = 3
                        ###thread_test = check_processes(process_list)
                        ###
                        # if client_intl_acc_list != []:
                        #     # test to check if threads are running
                        #     thread_test = t_nat.is_alive() or t_ato.is_alive() or t_client_intel.is_alive() or t_accounts.is_alive()
                        # else:
                        #     thread_test = t_nat.is_alive() or t_ato.is_alive() or t_client_intel.is_alive()
                else:
                    # if client intel was not chosen, creating empty account list
                    client_intl_acc_list = []
                    ###thread_test = t_nat.is_alive() or t_ato.is_alive()
                try:
                    stdscr.addstr(0, 0, "{}".format(banner[6:-27]), curses.color_pair(4))
                    stdscr.addstr(16, 0, "{}".format('Author: Elad Shuster'), curses.color_pair(2))
                    stdscr.addstr(18, 0, "[*] Data Center & Priority:", curses.color_pair(5))
                    stdscr.addstr(19, 0, "{}, {}".format(args.datacenter, args.priority), curses.color_pair(6))
                    stdscr.addstr(21, 0, "[*] IP Addresses Queried:", curses.color_pair(5))
                    stdscr.addstr(22, 0, "{}".format(query_ips), curses.color_pair(6))
                    stdscr.addstr(24, 0, "[*] DDC Timestamps Used:", curses.color_pair(5))
                    if 'time' in args:
                        stdscr.addstr(25, 0, "{} - {}".format(query_start_time_for_display, query_end_time_for_display),
                                      curses.color_pair(6))
                    else:
                        stdscr.addstr(25, 0, "{} - {}".format('ts >= @day_ago', 'ts < @now'),
                                      curses.color_pair(6))
                    stdscr.addstr(27, 0, '[*] "Days Ago" Queried From Client Intel:', curses.color_pair(5))
                    if 'clientintl_daysago' in args:
                        stdscr.addstr(28, 0, "{} Days Ago".format(args.clientintl_daysago), curses.color_pair(6))
                    else:
                        stdscr.addstr(28, 0, "Querying Client Intel Was Not Enabled In Script Arguments (-c [DAYSAGO])",
                                      curses.color_pair(3))
                    stdscr.addstr(30, 0, "[*] Query Status Monitor:", curses.color_pair(5))
                    stdscr.addstr(31, 0, nat_line[:200], curses.color_pair(nat_c))
                    stdscr.addstr(32, 0, ato_line[:200], curses.color_pair(ato_c))
                    if 'clientintl_daysago' in args:
                        stdscr.addstr(33, 0, client_line[:200], curses.color_pair(client_c))
                        stdscr.addstr(34, 0, accounts_line[:200], curses.color_pair(acc_c))
                        stdscr.addstr(35, 0, evidence_line[:200], curses.color_pair(evidence_c))
                    else:
                        stdscr.addstr(33, 0, '[*] Querying Client Intel Was Not Enabled In Script Arguments (-c [DAYSAGO])',
                                      curses.color_pair(3))
                        stdscr.addstr(34, 0, '[*] Attacked Accounts Query Is Based On Client Intel Results',
                                      curses.color_pair(3))
                        stdscr.addstr(35, 0, '[*] Evidence Properties Query Is Based On Client Intel Results',
                                      curses.color_pair(3))
                    # stdscr.addstr(23, 0, str(t_nat.is_alive()))
                    # stdscr.addstr(24, 0, str(t_ato.is_alive()))
                    # stdscr.addstr(25, 0, str(t_client_intel.is_alive()))
                    # stdscr.addstr(26, 0, str(thread_test))
                    stdscr.refresh()
                    sleep(0.2)
                    stdscr.clear()
                except:
                    stdscr.addstr(0, 0, "[*] Error")
                    stdscr.refresh()
                    sleep(0.2)
                    stdscr.clear()
                thread_test = check_processes(process_list)
                if not thread_test:
                    break
    finally:
        curses.nocbreak();
        curses.echo()
        curses.endwin()


##### Proccess NAT query results
if not args.debug: # in debug mode results are already read from a file
    nat_query_content = read_query_results(nat_result_file)

if len(nat_query_content) == 1:
    print "{}[*] NAT Query Returned No Results!{}".format(red, white)
    nat_query_success = 0
elif len(nat_query_content) == 0:
    print "{}[*] NAT Query Failed!{}".format(red, white)
    nat_query_success = 0
else:
    nat_query_success = 1
    parsed_content = [] # initializing a list for query results + parsed ua data

    # initializing empty variables for statistics later on in the code
    os_list = []
    os_count = defaultdict(int)
    device_list = []
    device_count = defaultdict(int)
    browser_list = []
    browser_count = defaultdict(int)
    ua_list = []
    account_subvector_list = []
    ad_tech_account_counter = 0
    ad_tech_uas = [] # list of unique user agents in the Advertising Technology sub-vector
    ad_tech_tc = 0
    non_ad_tc = 0
    ip_dict = {}
    # add header to parsed query result file
    headers = ['IP', 'Account_Name', 'Sub_Vertical',
               'User_agent', 'TOTAL_REQUESTS', 'Company', 'Country', 'Domain', 'Network_Type', 'Asnum', 'OS', 'Device', 'Browser', 'Browser_Version']
    write_row(parsed_result_file, headers)

    for line in nat_query_content[1:]: # ignore header line
        data = line.strip('\n').split('\t') # split TAB delimited data to columns
        parsed_ua = parse_ua(data[3]) # parse user agent metadata

        # create a list of IP[s]
        if data[0] not in ip_dict:
            ip_dict[data[0]] = [data[5], data[6], data[7], data[8], data[9]]

        # store distinct values of os, device, browser family, account names-->subvectors and user agents
        if parsed_ua[0] not in os_list:
            os_list.append(parsed_ua[0])
        if parsed_ua[1] not in device_list:
            device_list.append(parsed_ua[1])
        if parsed_ua[2] not in browser_list:
            browser_list.append(parsed_ua[2])
        if data[2] == '':
            account_vector = "{} --> {}".format('Sub-Vertical Not Found', data[1])
        else:
            account_vector = "{} --> {}".format(data[2],data[1])
        if account_vector not in account_subvector_list:
            account_subvector_list.append(account_vector)
            if data[02] == 'Advertising Technology':
                ad_tech_account_counter += 1 # incerement account counter
                if data[3] not in ad_tech_uas:
                    ad_tech_uas.append(data[3]) # add to list of unique user agents in account advertising
                ad_tech_tc += int(data[4])
            else:
                non_ad_tc += int(data[4])
        # create a list of distinct user agents
        if data[3] not in ua_list:
            ua_list.append(data[3])
            os_count[parsed_ua[0]] += 1
            device_count[parsed_ua[1]] += 1
            browser_count[parsed_ua[2]] += 1
        newline = data + parsed_ua
        parsed_content.append(newline)
        # write data to parsed result text file
        write_row(parsed_result_file, newline)

    if args.database:   # if the -db flag was given as an argument - insert parsed results into MySQL DB
        try:
            # DB Connection
            try:
                print ("{}[*] Adding NAT results to MySQL DB.".format(yellow))
                db = MySQLdb.connect(**CONFIG)
            except mysql.connector.errors.ProgrammingError:
                # create database and if doesn't exist
                print("[*] Creating database")
                db = MySQLdb.connect(host="localhost", user=DB_USER, passwd=DB_PASS)
                cursor = db.cursor(buffered=True)
                cursor.execute("CREATE DATABASE IF NOT EXISTS " + DB_NAME + ";")
                db = MySQLdb.connect(**CONFIG)
            db_cursor = db.cursor()
        except:
            print "{}[*] ERROR Connecting to the MySQL DB!".format(red)

        # Create table if not exists
        command = "CREATE TABLE IF NOT EXISTS nat_detection (ip VARCHAR(16), account_name TEXT, sub_vertical " \
                  "TEXT, user_agent TEXT, total_requests INT, company TEXT, country TEXT, domain TEXT, " \
                  "network_type, TEXT, asnum TEXT, os TEXT, device TEXT, browser TEXT, browser_version " \
                  "TEXT, query_file TEXT)"
        try:
            db_cursor.execute(command)
        except:
            print "{}[*] ERROR CREATING net_detection MySQL TABLE.".format(red)
            print command

        # bulk load parsed results from the tab delimited file created
        command = "LOAD DATA LOCAL INFILE '{}' INTO TABLE `nat_detection` FIELDS TERMINATED BY '\t' " \
                  "ENCLOSED BY '\"' LINES TERMINATED BY '\\n' IGNORE 1 LINES (`ip`, `account_name`, `sub_vertical`, " \
                  "`user_agent`, " \
                  "`total_requests`, `os`, `device`, `browser`, `browser_version`) SET `query_file` = '{}';".format(
                    os.path.abspath(parsed_result_file), query_file)
        try:
            print "{}[*] Importing the data:\n{}{}".format(yellow,cyan,command)
            db_cursor.execute(command)
            print "{}[*] Done Loading Successfully".format(green)
        except:
            print "{}[*] ERROR LOADING THE DATA INTO MySQL DB.".format(red)
            print command

##### Proccess ATO query Results
if not args.debug: # in debug mode results are already read from a file
    ato_query_content = read_query_results(ato_result_file)

if len(ato_query_content) == 1:
    print "{}[*] ATO Query Returned No Results!{}".format(red, white)
    ato_query_success = 0
elif len(nat_query_content) == 0:
    print "{}[*] ATO Query Failed!{}".format(red, white)
    ato_query_success = 0
else:
    ato_query_success = 1
    ato_hosts = 0
    ato_emails = 0
    for line in ato_query_content[1:]:
        data = line.strip('\n').split('\t')
        # get distinct hosts
        ato_emails += int(data[2])
        ato_hosts += int(data[1])

#### Proccess Accounts query results
if not args.debug: # in debug mode results are already read from a file
    if client_intl_acc_list != []:
        accounts_query_results = read_query_results(accounts_result_file)
        if len(accounts_query_results) == 1:
            print "{}[*] Attacked Accounts Query Returned No Results!{}".format(red, white)
        elif len(accounts_query_results) == 0:
            print "{}[*] Attacked Accounts Query Failed!{}".format(red, white)
        else:
            attacked_accounts = {}
            for line in accounts_query_results[1:]:
                acc_data = line.strip('\n').split('\t')
                attacked_accounts[acc_data[2]] = acc_data[1]
    else:
        # client intl query failed or returned zero lines - there is no point in fetching account results
        accounts_query_results = []
        print "{}[*] Attacked Accounts Query Did Not Run Since No Attacked Accounts Were Identified In Client Intel " \
              "Results {}".format(red, white)

##### PRINT END REPORT ######

#print "{}{}".format(purple,"-"*50)
if nat_query_success:
    print "\n{0}{1} User-Agent Analysis {1}".format(purple,"="*20)
    print "{0}OS Type Count: {1}[{2}]{0} - {1}{3}".format(yellow,cyan,len(os_list), os_list)
    print "{0}Device Type Count: {1}[{2}]{0} - {1}{3}".format(yellow,cyan,len(device_list), device_list)
    print "{0}Browser Count: {1}[{2}]{0} - {1}{3}".format(yellow,cyan,len(browser_list), browser_list)
    print "{}User Agent Count: {}{}".format(yellow,cyan,len(ua_list))

    print "\n{}OS Distribution: [".format(yellow),
    # count dict values to avoid printing last ,
    key_counter = len(os_count.keys())
    for k,v in os_count.iteritems():
        print "{}{}: {}{}".format(green, k, cyan, v),
        key_counter -= 1
        if key_counter != 0:
            print ",",
    print "{} ]".format(yellow)

    print "\n{}Device Type Distribution: [".format(yellow)
    # count dict values to avoid printing last ,
    key_counter = len(device_count.keys())
    for k,v in device_count.iteritems():
        print "{}{}: {}{}".format(green, k, cyan, v),
        if key_counter != 0:
            print ",",
    print "{} ]".format(yellow)

    print "\n{}Browser Distribution: [".format(yellow),
    # count dict values to avoid printing last ,
    key_counter = len(browser_count.keys())
    for k,v in browser_count.iteritems():
        print "{}{}: {}{}".format(green, k, cyan, v),
        if key_counter != 0:
            print ",",
    print "{} ]".format(yellow)

    print "\n{}User Agent List:".format(yellow)
    for ua in ua_list:
        print "{}[+] {}{}".format(green, cyan, ua)

print "\n{0}{1} Attack Analysis {1}".format(purple, "=" * 20)

if client_query_success:
    print "{}Attack Categories: {}{}".format(yellow,cyan,attack_categories_list)

if client_query_success and args.hosts == True:
    print "{}Hosts Attacked: {}{}\n{}Attacked Hosts List: {}".format(yellow,cyan,
            len(client_intl_host_list),yellow, cyan)
    for host in client_intl_host_list:
        print host

if client_query_success:
    print "{0}\nAccount & Sub-Vector Attacked: {1}{2}\n{1}".format(yellow,cyan,
            len(client_intl_acc_list),yellow, cyan)
    print_dict = defaultdict(str)
    for acc in client_intl_acc_list:
        # enter values from list to a dictionary for sorting by the value of the keys
        try:
            print_dict[attacked_accounts[acc.strip('"')]] = acc
        except:
            print_dict[acc] = acc
    for key in sorted(print_dict.keys()):
        try:
           print "{:<20}\t{:<40}\t{}".format(print_dict[key].strip('"'),attacked_accounts[print_dict[key].strip('"')],
                                             account_heuristics[print_dict[key]])
        except:
           print "{:<20}\t- (ACCOUNT DETAILS MISSING) \t{}".format(print_dict[key].strip('"'),account_heuristics[
               print_dict[key]])

print "\n{0}{1} Account Analysis {1}".format(purple, "=" * 20)

if nat_query_success:
    print "{0}Account & Sub-Vector Count: {1}{2}\n".format(yellow,cyan,
            len(account_subvector_list))
    for acc_subv in sorted(account_subvector_list):
        print acc_subv

    print "\n{0}{1} Business-Related Account Analysis {1}".format(purple, "=" * 20)
    business_acc_count = len(account_subvector_list) - ad_tech_account_counter
    print "{}Business-Related - Accounts Count: {}{}".format(yellow, cyan, len(account_subvector_list) -
    ad_tech_account_counter)
    print "{}Business-Related - Distinct User Agent Count: {}{}".format(yellow, cyan, len(ua_list) - len(
        ad_tech_uas))
    print "{}Business-Related - Total Request Count: {}{}".format(yellow, cyan, non_ad_tc)


    print "\n{0}{1} Ad-based Account Analysis {1}".format(purple, "=" * 20)
    print "{}Advertising Technology - Accounts Count: {}{}".format(yellow, cyan, ad_tech_account_counter)
    print "{}Advertising Technology - Distinct User Agent Count: {}{}".format(yellow, cyan, len(ad_tech_uas))
    print "{}Advertising Technology - Total Request Count: {}{}".format(yellow, cyan, ad_tech_tc)
    # print "{}User Agent List:".format(yellow)
    # for ua in ad_tech_uas:
    #     print "{}[+] {}{}".format(green, cyan, ua)

if ato_query_success:
    print "\n{0}{1} Login Data (from ATO table) {1}".format(purple, "=" * 20)
    print "{}Total Hosts Logged Into: {}{}".format(yellow, cyan, ato_hosts)
    print "{}Number Of Distinct Emails: {}{}".format(yellow, cyan, ato_emails)
    print "{}Distribution: [{}".format(yellow, cyan),
    line_counter = len(ato_query_content[1:])
    for line in ato_query_content[1:]:
        data = line.strip('\n').split('\t')
        print "{}'{}': {}{}".format(cyan,data[0],pink,data[3]),
    print "{}]".format(yellow)
else:
    print "\n{0}{1} Login Data (from ATO table) {1}".format(purple, "=" * 20)
    print "{}No ATO Data".format(yellow)

print "\n{0}{1} IP Edgescape Data {1}".format(purple, "=" * 20)
print "{}{:<16}\t{:<30}\t{:<15}\t{:<15}\t{:<15}\t{:<15}".format(yellow,'IP', 'Company', 'Country', 'Domain',

                                                                'Network_Type', 'Asnum')
if nat_query_success:
    for k,v in ip_dict.iteritems():
        print "{}{:<16}\t{:<30}\t{:<15}\t{:<15}\t{:<15}\t{:<15}".format(cyan, k, v[0], v[1], v[2], v[3], v[4])


if nat_query_success:
    print "\n{0}{1} NAT GUESS {1}".format(purple, "=" * 20)

    if business_acc_count < 10:
        msg = 'IP[s] Does Not Seem To Be Shared'
    elif business_acc_count >= 10 and business_acc_count <= 30:
        msg = 'IP[s] Seem To Be a Small Sized NAT'
    elif business_acc_count >= 30 and business_acc_count <= 100:
        msg = 'IP[s] Seem To Be a Medium Sized NAT'
    elif business_acc_count > 30 and business_acc_count <= 150:
        msg = 'IP[s] Seem To Be a Large Sized NAT'
    elif business_acc_count > 150:
        msg = 'Unable To Decide - Business-Related Account Count Is Too High!'

    print "{}Business-Related Accounts Count Of {} for IP[s] {} Indicates:\n{}{}".format(yellow, business_acc_count,
                                                                                         str(query_ips), cyan, msg)

print '\n{}[*] Query Results With Parsed User Agent Data Saved to:\n{}{}{}'.format(pink, green, os.getcwd()+"/"+parsed_result_file, white)
if args.database:
    print "{}[*] Query Results With Parsed User Agent Data Inserted to MySQL DB '{}' into `{}` table{}\n".format(
            pink, DB_NAME, 'nat_detection', white)

if args.gather and client_query_success:
    print '\n{}[*] Evidence Properties Query Results Saved to:\n{}{}{}\n'.format(pink, green, os.getcwd()+"/"+evidence_result_file, white)