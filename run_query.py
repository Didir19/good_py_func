#!/usr/bin/python
import sys
import os
import time
import subprocess
import getpass
import re
import fcntl
import imp
import argparse
import datetime
import calendar
import signal

VERSION = '2.0'

# Consts
query_path = 'default'
insert_to_db = False
selected_data_center = 'virginia'
table = 'default'
server = ''
path_in_server = ''
job_num = ''
log_path = ''
f_flag = False
proc_list = []
temp_file = ''
silent_mode = False
priority = 'NORMAL'  # VERY_HIGH, HIGH, NORMAL, LOW, VERY_LOW
log = False

usage = """
    Usage : run_query.py [-f <query file>] [-h] [-s] [-d] [-l] [-p] [data center]

    Available data centers :
        * virginia (default)
        * san jose

    -f, --file: Query File.

    -d, --database: Insert query results directly to local database.

    -s, --silent: Script will run without the voices.

    -p, --priority: Sets the query's priority in hive. Possible values: VERY_HIGH, HIGH, NORMAL, LOW, VERY_LOW.
                Case sensitivity isn't important.

    -l, --log: Write all script's output to a log file. The log file has the same filename as the query file and created in the same path as the query file.

    Timestamp keyword:

        @now

        @hour_ago

        @day_ago

        @week_ago

        @month_ago

        @{1-25}_hours_ago

        @{1-32}_days_ago

        @{1-13}_weeks_ago

        Full day:
            @<TABLE_NAME>.full_day: 22/1/17 --> ddc_nat.ts >= (22/01/2017 00:00) and ddc_nat.ts < (23/01/2017 00:00)

        Date:
            ts >= '@date: 4/1/17 8:30' --> ts >= '1483518600000'

        NOTE: For the 'Full day' and 'Date' timestamp keywords, you can put also only the day or day and month, and the current month and year will be filled automatically.

    -h, --help: How to use this script.

    """

def print2log(text):
    global log, log_file

    if log:
        open(log_file, 'a').write(text.decode('utf8'))
    else:
        print text

def tab_progress(str = ''):
    global temp_file
    f = re.sub('^\w+\.', "", os.path.basename(temp_file)[::-1])[::-1]
    if str == '':
        msg = "\033]0;" + f + "\007"
    else:
        msg = "\033]0;" + f + ": " + str + "\007"
    cmd = ['echo', '-n', msg]
    subprocess.Popen(cmd)


def init():
    global query_path, log_file, log
    global insert_to_db
    global selected_data_center
    global f_flag, silent_mode, priority

    parser = argparse.ArgumentParser(usage=usage, add_help=False)
    parser.add_argument("query_file", help="Query file")
    parser.add_argument("-s", "--silent", action="store_true", default=False, help="Script will run without the voices")
    parser.add_argument("-d", "--database", action="store_true", help="Insert query results directly to local database")
    parser.add_argument("-p", "--priority", type=lambda s: s.upper(), choices=['VERY_HIGH', 'HIGH', 'NORMAL', 'LOW', 'VERY_LOW'],
                        default="NORMAL", help="Sets the query's priority in hive")
    parser.add_argument("datacenter", nargs='?', type=lambda s: s.lower(), choices=["virginia", "sj"],
                        default="virginia", help="Sets on which datacenter run the query")
    parser.add_argument("-l", "--log", action="store_true", default = False, help="Log script output to file")
    args = parser.parse_args()
    # print str(opts)
    # print str(args)

    query_path = args.query_file
    selected_data_center = args.datacenter
    insert_to_db = args.database
    priority = args.priority
    silent_mode = args.silent
    if args.log:
        log = args.log
        log_file = "{}.log".format(args.query_file)

def check_date(date):
    now = calendar.timegm(datetime.datetime.now().timetuple())
    now = datetime.datetime.fromtimestamp(now)
    diff = now - date
    return 0 <= diff.days <= 30


def ts_from_date_and_time(dt, diff = ""):
    ts = calendar.timegm(dt.timetuple())
    ts *= 1000
    if diff != "":
        time_sp = diff.split(':')
        time_sp = [int(x) for x in time_sp]
        if 0 <= time_sp[0] <= 24 and 0 <= time_sp[1] <= 59:
            ts += (time_sp[0] * 3600000)
            ts += (time_sp[1] * 60000)
        else:
            print("Invalid given time")
            sys.exit(2)

    return ts


def full_day_string(table, dt):
    if dt == 'yesterday':
        d = datetime.datetime.utcnow() - datetime.timedelta(days=1)
        d = datetime.datetime(d.year, d.month, d.day)
        end_dt = d + datetime.timedelta(days=1)
        end_dt = calendar.timegm(end_dt.timetuple())
        end_dt *= 1000
        from_dt = calendar.timegm(d.timetuple())
        from_dt *= 1000
    else:
        end_dt = datetime.datetime(dt.year, dt.month, dt.day) + datetime.timedelta(days=1)
        end_dt = calendar.timegm(end_dt.timetuple())
        end_dt *= 1000
        from_dt = calendar.timegm(dt.timetuple())
        from_dt *= 1000
    return "{tab}.ts >= '{from_time}' AND {tab}.ts < '{to_time}'".format(tab=table, from_time=from_dt, to_time=end_dt)



def date_from_string(dt_str):
    regx = re.compile('[./-]')
    dt = regx.split(dt_str)
    dt_len = len(dt)

    if dt_len < 1 or dt_len > 3:
        print("Error")
        sys.exit(1)
    elif dt_len == 1:
        d = dt[0].zfill(2)
        m = datetime.datetime.now().month
        y = datetime.datetime.now().year
    elif dt_len == 2:
        d = dt[0].zfill(2)
        m = dt[1].zfill(2)
        y = datetime.datetime.now().year
    else:
        d = dt[0].zfill(2)
        m = dt[1].zfill(2)
        y = '20' + dt[2].zfill(2) if len(dt[2]) == 2 else dt[2]
    try:
        dt = datetime.datetime(year=int(y), month=int(m), day=int(d))
    except ValueError:
        print("Given date is invalid!")
        sys.exit(1)
    return dt


def parse_date(query):
    global table

    hive_load_offset = 3600 * 4
    if not log:
        print "Applying Hive load offset of %d secs." % hive_load_offset

    if query.count("@date:"):
        date = re.findall("('?@date:\s*([^\s']+)(\s?([^']+))?'?)", query, re.IGNORECASE)
        if date:
            for index, shit in enumerate(date):
                dt = date_from_string(shit[1])
                if len(shit) > 2:
                    dt = ts_from_date_and_time(dt, shit[2])
                else:
                    dt = ts_from_date_and_time(dt)

                query = re.sub(shit[0], "'" + str(dt) + "'", query, 1)
        else:
            print("No given date")
            sys.exit(1)

    if query.count("@end_date"):
        date_str = raw_input('end date :')
        query = query.replace("@end_date", str(get_date(date_str)))

    if query.count(".full_day:"):
        date = re.findall("'?@([^\.]+)+\.full_day.([^']+)'?", query, re.IGNORECASE)
        if date:
            for index, shit in enumerate(date):
                table = shit[0]
                dt = shit[1]
                if dt != 'yesterday':
                    dt = date_from_string(shit[1])
                    if not check_date(dt):
                        print("Invalid date! No info available! (30 days limit)")
                        sys.exit(1)
                date_str = full_day_string(table, dt)
                query = re.sub("'?@([^\.]+)\.full_day.([^']+)'?", date_str, query, 1)
        else:
            print("No given date")
            sys.exit(1)

    token_to_magic_words = {
        "@now": 'now',
        "@week_ago": 'week ago',
        "@month_ago": 'month ago',
        "@day_ago": 'day ago',
        "@hour_ago": 'hour ago',
        "@30_mins_ago": '30 minutes ago',
    }

    for x in range(1, 32):
        token_to_magic_words["@{}_days_ago".format(x)] = "{} days ago".format(x)
    for x in range(1, 13):
        token_to_magic_words["@{}_weeks_ago".format(x)] = "{} weeks ago".format(x)
    for x in range(1, 25):
        token_to_magic_words["@{}_hours_ago".format(x)] = "{} hours ago".format(x)

    for k in token_to_magic_words:
        if query.count(k):
            date_str = token_to_magic_words[k]
            query = query.replace(k, str(get_date(date_str)))

    return query


def get_date(date_str):
    hive_load_offset = 3600 * 4
    # hive_load_offset = 0

    secondsPerDay = 3600 * 24


    magic_words = {
        "now": 0,
        "week ago": secondsPerDay * 7,
        "week ago + 1": secondsPerDay * 8,
        "month ago": secondsPerDay * 14,
        "day ago": secondsPerDay,
        "day ago + 1": secondsPerDay * 2,
        "hour ago": 3600,
    }
    for x in range(1, 32):
        magic_words["{} days ago".format(x)] = x * secondsPerDay
    for x in range(1, 13):
        magic_words["{} weeks ago".format(x)] = x * 7 * secondsPerDay
    for x in range(1, 13):
        magic_words["{} weeks ago + 1".format(x)] = (x * 7 + 1) * secondsPerDay
    for x in range(1, 25):
        magic_words["{} hours ago".format(x)] = x * 3600

    current_ts = int(time.time())

    if date_str == '':
        date_str = "now"

    if date_str not in magic_words:
        print "wrong date keyword supplied. available keywords (default is now):"
        for k in magic_words.keys():
            print k

        sys.exit()

    ts = current_ts - magic_words[date_str] - hive_load_offset
    return ts * 1000


def add_query_path_comment(query):
    query = "-- Query file name {} \n {}".format(query_path, query)
    return query


def add_headers_names(query):
    query = "set hive.cli.print.header=true; \n {}".format(query)
    return query


def add_audit_info(query):
    query = "-- %s \n %s" % (getpass.getuser(), query)
    return query


def add_priority(query, prio):
    query = "set mapreduce.job.priority=%s; \n %s" % (prio, query)
    return query


def system_call(command):
    global proc_list

    # we want to control the keyboard interrupt and not passing it to the subprocess
    # preexec_fn=os.setpgrp - causing the subprocess not getting interrupts from parent
    p = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True, preexec_fn=os.setpgrp)
    proc_list.append(p)
    return p


def non_block_read(output):
    fd = output.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    try:
        return output.read()
    except:
        return ""


def kill_job():
    global job_num
    global proc_list
    global log_path

    ans = '###'
    while ans not in ('J', 'j', 'R', 'r', 'C', 'c'):
        ans = raw_input("What do you want to do?\nkill Job, kill Run_query or Cancel\n"
                        "Answer [J/R/C]:")
        if ans in ('R', 'r'):
            print("Terminating ONLY run_query, Hive job still running")
            for proc in proc_list:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGTERM)
            sys.exit(1)

    if ans in ('J', 'j'):
        print("Killing...")
        for proc in proc_list:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
        cmd = 'scp -r -S gwsh %s:%s/progress.log %s.log.tmp' % (server, path_in_server, query_path)
        proc = system_call(cmd)
        (out, err) = proc.communicate()
        for line in reversed(open("%s.log.tmp" % query_path).readlines()):
            job = re.findall('Starting Job = ([^,]+),', line)
            if job:
                print("Job: " + job[0])
                cmd = 'gwsh %s "/a/csi-hive-gateway/bin/local_kill_job.sh %s"' % (server, job[0])
                os.system(cmd)
                if os.path.isfile("%s.log.tmp" % query_path):
                    os.remove("%s.log.tmp" % query_path)
                break
        if os.path.isfile("%s" % temp_file):
            os.remove("%s" % temp_file)
        sys.exit(1)


def main():
    global query_path, log_file, log
    global selected_data_center
    global insert_to_db
    global job_num, server, path_in_server, log_path, temp_file
    global silent_mode

    data_centers = {
        # "virginia": "173.223.226.29",
        # "chicago": "96.6.126.125"
        "virginia": "research-csi-virginia.csi.akadns.net",
        "chicago": "research-csi-chicago.csi.akadns.net",
        "sj": "research-csi-sj.csi.akadns.net"
    }

    cmd = "host " + data_centers[selected_data_center]
    remote_ip = subprocess.check_output(cmd, shell=True)
    remote_ip = re.findall('has address (.*)$', remote_ip)
    if not remote_ip:
        tab_progress("Error!")
        print("Error: Couldn't find datacenter's IP address")

    remote_ip = remote_ip[0]
    original_query = open(query_path, "rb").read()

    modified_query = parse_date(original_query)

    modified_query = add_query_path_comment(modified_query)
    # modified_query = add_audit_info(modified_query)
    # modified_query = add_headers_names(modified_query)
    # modified_query = add_priority(modified_query, priority)

    output = ""
    got_path = False
    got_jobid = False

    temp_file = query_path + "_" + selected_data_center + ".tmp"
    tab_progress()
    # check if tmp file exists already
    if os.path.exists(temp_file):
        ans = '###'
        while ans not in ('C', 'c', 'R', 'r'):
            ans = raw_input("The same query was launched on " + selected_data_center + " on the:\n" + \
                            time.ctime(os.path.getctime(temp_file)) + \
                            "\nDo you want to check the results of the previous query or restart it?\n" \
                            "Answer [C or R]:")
        if ans in ('C', 'c'):
            with open(temp_file, "r") as t_file:
                for line in t_file:
                    if line.count("PATH:"):
                        temp = line.strip()
                        server = re.sub(r"PATH:", "", temp)
                        server = re.sub(r":.*$", "", server)
                        path_in_server = re.sub(r"^[^/]+", "", temp)

                    if line.count("LOG:"):
                        log_path = line.strip()
                        log_path = re.sub("LOG:", "", log_path)

                cmd = 'gwsh %s "tail %s"' % (server, log_path)
                proc = system_call(cmd)
                (out, err) = proc.communicate()
                res_code = re.findall('Hive exit code is:(\d+)', out)
                if res_code:
                    if res_code[0] == '0':
                        # Query SUCCEEDED
                        print2log("Job succeeded")
                        os.system('scp -r -S gwsh %s:%s/output.gz %s.out.gz' % (server, path_in_server, query_path))
                        os.system('gunzip -f %s.out.gz' % query_path)
                        os.system('rm %s' % temp_file)
                        os.system('gwsh %s "rm -rf %s*"' % (server, path_in_server))

                        # Insert to local database
                        if insert_to_db:
                            cmd = "csv2mysql.py -f %s" % query_path + '.out'
                            os.system(cmd)

                        if not silent_mode:
                            os.system('say "query completed" -v Samantha; printf "\a"')
                        sys.exit(0)
                    else:
                        print("Process was probably KILLED or FAILED. Starting from scratch...")
                        print("Starting new job")
                        print("Query's priority: " + priority)
                        # create temporary query file
                        open(temp_file, "wb").write(modified_query)

                        print modified_query
                        # return

                        # upload query
                        print query_path
                        print "Running query on: " + remote_ip
                        p = system_call('enter_the_hive.sh --query_file %s -tm %s -priority %s' % (temp_file, remote_ip, priority))
                else:
                    print ("Job still running\nTrying to resume...")
                    cmd = 'gwsh %s "tail -f %s"' % (server, log_path)
                    got_jobid = True
                    p = system_call(cmd)
        else:
            print("Starting new job")
            print("Query's priority: " + priority)
            # create temporary query file
            open(temp_file, "wb").write(modified_query)

            print modified_query
            # return

            # upload query
            print query_path
            print "Running query on: " + remote_ip
            p = system_call('enter_the_hive.sh --query_file %s -tm %s -priority %s' % (temp_file, remote_ip, priority))
    else:
        if not log:
            print("Starting new job")
            print("Query's priority: " + priority)
            # create temporary query file
            open(temp_file, "wb").write(modified_query)

            print modified_query
            # return

            # upload query
            print query_path
            print "Running query on: " + remote_ip
            p = system_call('enter_the_hive.sh --query_file %s -tm %s -priority %s' % (temp_file, remote_ip, priority))
        else:
            open(temp_file, "wb").write(modified_query)
            p = system_call('enter_the_hive.sh --query_file %s -tm %s -priority %s' % (temp_file, remote_ip, priority))

    kill = False
    interrupts = 0
    max_interrupts = 10
    while True:
        try:
            if p.poll() is not None:
                tab_progress("Error!")
                print "query execution process died. aborting."
                sys.exit(1)

            if interrupts > max_interrupts:
                tab_progress("DONE")
                print "too many tries ... abort."
                sys.exit(1)

            time.sleep(0.5)
            delta = non_block_read(p.stdout)
            output += delta

            if not got_path and output.count("Making temp workspace"):
                address = re.findall('Making temp workspace ([^\s]+) on remote host ([\d.]+)', output)
                path = "csitr@%s:%s/" % (address[0][1], address[0][0])
                open(temp_file, "a").write("\nPATH:" + path)
                path_in_server = address[0][0]
                server = "csitr@%s" % address[0][1]
                open(temp_file, "a").write("\nLOG:" + os.path.join(address[0][0], "progress.log"))
                log_path = os.path.join(address[0][0], "progress.log")
                got_path = True
            if not got_jobid and output.count("Starting Job"):
                got_jobid = True
                if not log:
                    print("\n########################################")
                    print("##### YOU CAN EXIT NOW, IF YOU WANT ####")
                    print("########################################\n")

            if output.count("FAILED: "):
                if delta != '' and not kill:
                    if not log:
                        print delta,
                        print "Query Failed! Exiting..."
                        tab_progress("Error!")
                    else:
                        print2log(delta)
                        print2log("Query Failed! Exiting...")

                    if not silent_mode:
                        os.system('say -v "Ralph" "error"; say -v "Hysterical" "hahaha"; printf "\a"')

                    if os.path.isfile(temp_file):
                        os.remove(temp_file)
                    sys.exit(1)

            if output.count("Hive exit code is:"):
                if delta != '' and not kill:
                    res_code = re.findall('Hive exit code is:(\d+)', output)
                    if res_code:
                        if res_code[0] != '0':
                            if not log:
                                print delta,
                                print "Query Failed! Exiting..."
                                tab_progress("Error!")
                            else:
                                print2log(delta)
                                print2log("Query Failed! Exiting...")

                            if not silent_mode:
                                os.system('say -v "Ralph" "error"; say -v "Hysterical" "hahaha"; printf "\a"')

                            if os.path.isfile(temp_file):
                                os.remove(temp_file)
                            sys.exit(1)

            if output.count("Query Result SCP syntax --> "):
                if delta != '' and not kill:
                    if not log:
                        print delta,
                    else:
                        print2log(delta)

                remote_path = re.findall("Query Result SCP syntax --> scp -S gwsh csitr@[^:]+?:(.+?)\n", output)

                if log:
                    os.system('scp -r -S gwsh csitr@%s:%s %s.out.gz >> %s' % (remote_ip, remote_path[0], query_path, log_file))
                else:
                    os.system('scp -r -S gwsh csitr@%s:%s %s.out.gz' % (remote_ip, remote_path[0], query_path))
                os.system('gunzip -f %s.out.gz' % query_path)
                os.system('rm %s' % temp_file)
                os.system('gwsh csitr@%s "rm -rf %s*"' % (remote_ip, remote_path[0]))

                # Insert to local database
                if insert_to_db:
                    cmd = "csv2mysql.py -f %s" % query_path + '.out'
                    os.system(cmd)
                tab_progress("Finished")

                if not silent_mode:
                    os.system('say "query completed" -v Samantha; printf "\a"')
                break

            if delta != '':  # and not kill:
                if not log:
                    print delta,
                else:
                    print2log(delta)
                percent = re.findall(".+map = (\d+)%,  reduce = (\d+)%", delta)
                if percent:
                    tab_progress("Map: " + percent[0][0] + "% Reduce: " + percent[0][1] + "%")
                    msg = "\n"+"Map: " + percent[0][0] + "% Reduce: " + percent[0][1] + "%"
        except KeyboardInterrupt:
            interrupts += 1
            kill = True
            if not got_jobid:
                print("Wait until you see the 'You can exit' message")
            else:
                kill_job()
            continue

init()
if not log:
    print "Run_Query.py Version " + VERSION + '\n'
main()
