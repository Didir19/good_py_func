#!/usr/bin/env python
'''
This is a wrapper script for the nat detection query.
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
import threading
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

date_time = strftime("%d%m%y-%H%M%S", localtime())
query_file = 'nat_detect_query_{}.hql'.format(date_time)
query_results = query_file+".out"
parsed_result_file = 'nat_detection_results_{}.txt'.format(date_time)
client_query_success = 0
ato_query_success = 0
nat_query_success = 0


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


usage = """{}

 _   _       _    ______     _            _   _
| \ | |     | |   |  _  \   | |          | | (_)
|  \| | __ _| |_  | | | |___| |_ ___  ___| |_ _  ___  _ __
| . ` |/ _` | __| | | | / _ \ __/ _ \/ __| __| |/ _ \| '_ \\
| |\  | (_| | |_  | |/ /  __/ ||  __/ (__| |_| | (_) | | | |
\_| \_/\__,_|\__| |___/ \___|\__\___|\___|\__|_|\___/|_| |_|


 _    _
| |  | |
| |  | |_ __ __ _ _ __  _ __   ___ _ __
| |/\| | '__/ _` | '_ \| '_ \ / _ \ '__|
\  /\  / | | (_| | |_) | |_) |  __/ |
 \/  \/|_|  \__,_| .__/| .__/ \___|_|
                 | |   | |
                 |_|   |_|

{}Author: Elad Shuster
[*] AKAMAI - Threat Research [*]

{}usage:   {}nat_detect.py  [-c DAYS_AGO] [-db] [-dh] [-g] [-q] [-t date,time,increment,unit] [-p] [PRIORITY]
         [-dc] [DATACENTER] ip[s]
{}example: {}nat_detect.py -db -p very_high -dc sj -c 10 -t thursday,09:00,1,d 1.1.1.1, 2.2.2.2-2.2.2.50, 3.3.3.0/24

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
  {}-p [PRIORITY], --priority [PRIORITY]          {}specify query priority (default = 'normal')
  {}-q, --quiet                                   {}quiet mode - suppress run_query's screen output
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
    parser.add_argument('-p', '--priority', action='store', default='normal', nargs='?', help="specify query priority")
    parser.add_argument('-q', '--quiet', action='store_true', default=False, help="quiet mode - suppress run_query's "
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

def run_query (query, tag):

    global args, quiet

    timestamp = strftime("%d%m%y-%H%M%S", localtime())

    # Initialize query files
    query_file = '{}_query_{}.hql'.format(tag,timestamp)
    result_file = '{}.out'.format(query_file)
    log_file = '{}_query_{}.log'.format(tag, timestamp)
    # write query to file
    with open(query_file, 'w') as q:
        q.write(query)

    if args.quiet == True:
        quiet = '> {}'.format(log_file)
    else:
        quiet = ''

    # run query
    print "{}[*] Running Query:\n{}{}{}".format(yellow, purple, query, cyan)
    command = 'run_query.py -p {} {} {} {}'.format(args.priority, query_file, args.datacenter, quiet)
    print "[*] {}".format(command)

    if args.quiet:
        t = threading.Thread(target=os_run_query, args=(command,))
        t.start()

        while t.isAlive():
            for c in itertools.cycle(['|', '/', '-', '\\']):
                if not t.is_alive():
                    break
                if os.path.exists(log_file):
                    with open(log_file, 'r') as log:
                        line = log.readlines()
                        if len(line) != 0:
                            line = line[len(line)-1].replace('\n','')
                        else:
                            line = ''
                else:
                    line = ''
                sys.stdout.write('{0}\r {1} Query Running {1} - {2}{3}'.format(pink, c, white, line))
                sys.stdout.flush()
                sleep(0.05)
            sys.stdout.write('\rDone!     ')
    else:
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
        return content

    if not args.debug:
        try:
            #os.system("rm {} {}".format(query_file, result_file))
            #print "{}[*] Removing query files...{}".format(yellow, white)
            pass
        except:
            print "{}[*] Error Deleting Query Files{}".format(red, white)
    print "{}[*] Query Ended Successfully!".format(green)

    return content


def read_file_lines(file):
    with open(file, 'r') as f:
        content = f.readlines()
    return content


### Main ###
args = parse_argument()

# check if quiet mode was enables
if args.quiet == True:
    quiet = '> /dev/null'
else:
    quiet = ''

if args.datacenter not in ('sj', 'virginia'):
    print "{}[*] ERROR - Invalid DC Chosen!".format(red)
    sys.exit(1)

banner = """{}
 _   _       _    ______     _            _   _
| \ | |     | |   |  _  \   | |          | | (_)
|  \| | __ _| |_  | | | |___| |_ ___  ___| |_ _  ___  _ __
| . ` |/ _` | __| | | | / _ \ __/ _ \/ __| __| |/ _ \| '_ \\
| |\  | (_| | |_  | |/ /  __/ ||  __/ (__| |_| | (_) | | | |
\_| \_/\__,_|\__| |___/ \___|\__\___|\___|\__|_|\___/|_| |_|


 _    _
| |  | |
| |  | |_ __ __ _ _ __  _ __   ___ _ __
| |/\| | '__/ _` | '_ \| '_ \ / _ \ '__|
\  /\  / | | (_| | |_) | |_) |  __/ |
 \/  \/|_|  \__,_| .__/| .__/ \___|_|
                 | |   | |
                 |_|   |_|

{}Author: Elad Shuster
""".format(green,pink)

print "{}{}{}".format(green, banner, white)
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
            print "{}[*] ERROR - Error Parsing ip / ip range - {}{}.".format(red,args.ips, white)
            print "{}[*] If the IP / IP Range was pasted from JIRA or other Web Page - Please Type Them By " \
                  "Manually! ".format(red, white)
            raise()
    else:
        ips.append(ip)

# validate ips
for ip in ips:
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
                                                 parsed_time.hour + 3, 0).strftime('%s') # adding 3 due to the GMT offset in Israel
            print "{}[*] NAT Query Start Time: {}{}".format(yellow, cyan, parsed_time.strftime("%a, %d %b %Y %H:%M:%S +0000"))
            if input_list[3] == 'h':
                # increment hours to end date (besides GMT offset)
                query_end_time = datetime.datetime(parsed_time.year, parsed_time.month, parsed_time.day,
                                        parsed_time.hour + int(input_list[2]) + 3, 0) # adding 3 due to the GMT offset in Israel
            elif input_list[3] == 'd':
                # increment days to start date
                query_end_time = datetime.datetime(parsed_time.year, parsed_time.month, parsed_time.day +
                                                   int(input_list[2]), parsed_time.hour + 3, 0) # adding 3 due to the GMT offset in Israel
            else:
                print "{}ERROR! Malformed ddc time parameter: {}".format(red, args.time)
                print time_error_msg
                sys.exit(1)
            print "{}[*] NAT Query End Time: {}{}".format(yellow, cyan,
                                                            query_end_time.strftime("%a, %d %b %Y %H:%M:%S +0000"))
            query_end_time = query_end_time.strftime('%s')
    nat_query_ts = "(ts>='{}' and ts<'{}')".format(int(query_start_time)*1000, int(query_end_time)*1000)
    print nat_query_ts
else:
    nat_query_ts = "ts>='@day_ago'"


# test if client_intl flag was specified
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
        clientintl_content = read_file_lines('client_intl')
    else:
        clientintl_content = run_query(clientintl_query, 'client_intel')

    client_intl_acc_list = []
    client_intl_host_list = []

    if len(clientintl_content) == 1:
        print "{}[*] client_intl Query Returned No Results!{}".format(red, white)
        client_query_success = 0
    elif len(clientintl_content) == 0:
        print "{}[*] client_intl Query Failed!{}".format(red, white)
        client_query_success = 0
    else:
        client_query_success = 1
        client_intl_heur_timestamps = []
        heuristic_hosts = defaultdict(list)  # dictionary of hosts per heuristic
        account_heuristics = defaultdict(list)  # dictionary of heuristics per account
        attack_categories_list = []
        for line in clientintl_content[1:]:  # ignore header line
            client_intl_data = line.strip('\n').split('\t') # split TAB delimited data to columns

            if client_intl_data[3].lower() == 'false':
                pass
            else:
                ts = int(client_intl_data[0])
                parsed_ts = datetime.datetime.fromtimestamp(int(ts) / 1000)
                rounded_ts = int(datetime.datetime(parsed_ts.year, parsed_ts.month, parsed_ts.day,
                                                   parsed_ts.hour, 0).strftime('%s'))

                if rounded_ts not in client_intl_heur_timestamps:
                    client_intl_heur_timestamps.append(rounded_ts)

                # parse the evidences field in client_intl
                client_intl_heur_dict = ast.literal_eval(client_intl_data[9])
                client_intl_heur_dict = client_intl_heur_dict[0]

                heuristic_name = client_intl_heur_dict['heuristic_name'][:client_intl_heur_dict['heuristic_name'].find(";")]

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

        if args.debug:
            accounts_query_results = read_file_lines('accounts_results')
        else:
            accounts_query_results = run_query(accounts_query, 'accounts')


        if len(accounts_query_results) == 1:
            print "{}[*] client_intl Query Returned No Results!{}".format(red, white)
        elif len(accounts_query_results) == 0:
            print "{}[*] client_intl Query Failed!{}".format(red, white)
        else:
            attacked_accounts = {}
            for line in accounts_query_results[1:]:
                acc_data = line.strip('\n').split('\t')
                attacked_accounts[acc_data[2]] = acc_data[1]

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
      WHERE {1}) t2 ON (t1.CPCODE = t2.CPCODE)
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
    nat_query_content = read_file_lines('nat_query')
else:
    nat_query_content = run_query(query, 'nat')

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

if args.debug:
    try:
        ato_query_content = read_file_lines('ato_query')
    except:
        print 'ATO Result File Not Found!'
        ato_query_content = ['']

    #ato_query_content = run_query(ato_query, 'ato')
else:
    ato_query_content = run_query(ato_query, 'ato')

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
        # enter to dictionary for sorting
        try:
            print_dict[attacked_accounts[acc.strip('"')]] = acc
        except:
            print_dict[acc] = acc
    for key in sorted(print_dict.keys()):
        try:
           print "{:<15}\t{:<40}\t{}".format(print_dict[key].strip('"'),attacked_accounts[print_dict[key].strip('"')],
                                             account_heuristics[print_dict[key]])
        except:
           print "{}\t-\t{}".format(print_dict[key].strip('"'),account_heuristics[print_dict[key]])

print "\n{0}{1} Account Analysis {1}".format(purple, "=" * 20)

if nat_query_success:
    print "{0}Account & Sub-Vector Count: {1}{2}\n".format(yellow,cyan,
            len(account_subvector_list))
    for acc_subv in sorted(account_subvector_list):
        print acc_subv

    print "\n{0}{1} Business-Related Account Analysis {1}".format(purple, "=" * 20)
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
        print "{}'{}': {}{}".format(cyan,data[0],pink,data[3])
else:
    print "\n{0}{1} Login Data (from ATO table) {1}".format(purple, "=" * 20)
    print "{}No ATO Data".format(yellow)

print "\n{0}{1} IP Edgescape Data {1}".format(purple, "=" * 20)
print "{}{:<16}\t{:<30}\t{:<15}\t{:<15}\t{:<15}\t{:<15}".format(yellow,'IP', 'Company', 'Country', 'Domain',  'Network_Type', 'Asnum')

if nat_query_success:
    for k,v in ip_dict.iteritems():
        print "{}{:<16}\t{:<30}\t{:<15}\t{:<15}\t{:<15}\t{:<15}".format(cyan, k, v[0], v[1], v[2], v[3], v[4])

print '\n{}[*] Query Results With Parsed User Agent Data Saved to:\n{}{}{}'.format(pink, green, os.getcwd()+"/"+parsed_result_file, white)
if args.database:
    print "{}[*] Query Results With Parsed User Agent Data Inserted to MySQL DB '{}' into `{}` table{}".format(
            pink, DB_NAME, 'nat_detection', white)


