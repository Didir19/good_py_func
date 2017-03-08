#!/usr/bin/python
import sys
import os
import time
import subprocess
import getpass
import re
import fcntl
VERSION='1.0'

def parse_date(query):
    
    if query.count("@start_date"):
        date_str = raw_input('start date :')
        query = query.replace("@start_date", str(get_date(date_str)))

    if query.count("@end_date"):
        date_str = raw_input('end date :')
        query = query.replace("@end_date", str(get_date(date_str)))


    token_to_magic_words = {
        "@now" : 'now',
        "@week_ago" : 'week ago',
        "@1_month_ago" : '1 month ago',
        "@day_ago" : 'day ago',
        "@hour_ago" : 'hour ago',
        "@30_mins_ago" : '30 minutes ago',
    }


    for x in range(1, 32):
        token_to_magic_words["@{}_days_ago".format(x)] = "{} days ago".format(x)
    for x in range(1, 6):
        token_to_magic_words["@{}_weeks_ago".format(x)] = "{} weeks ago".format(x)
    for x in range(1, 25):
        token_to_magic_words["@{}_hours_ago".format(x)] = "{} hours ago".format(x)


    for k in token_to_magic_words:
        if query.count(k):
            date_str = token_to_magic_words[k]
            query = query.replace(k, str(get_date(date_str)))

    return query

def get_date(date_str):
    
    
    hive_load_offset = 3600*4
    # hive_load_offset = 0
    
    secondsPerDay = 3600*24
    print "Applying Hive load offset of %d secs."%hive_load_offset

    magic_words = {
        "now" : 0,
        "week ago" : secondsPerDay*7,
        "week ago + 1" : secondsPerDay*8, 
        "1 month ago" : secondsPerDay*14,
        "day ago" : secondsPerDay,
        "day ago + 1" : secondsPerDay*2,
        "hour ago" : 3600,
    }
    for x in range(1, 32):
        magic_words["{} days ago".format(x)] = x*secondsPerDay
    for x in range(1, 6):
        magic_words["{} weeks ago".format(x)] = x*7*secondsPerDay
    for x in range(1, 6):
        magic_words["{} weeks ago + 1".format(x)] = (x*7+1)*secondsPerDay
    for x in range(1, 25):
        magic_words["{} hours ago".format(x)] = x*3600

    current_ts = int(time.time())
    
    if date_str == '':
        date_str = "now"

    if date_str not in magic_words:
        print "wrong date keyword supplied. available keywords (default is now):"
        for k in magic_words.keys():
            print k

        sys.exit()

    ts = current_ts - magic_words[date_str] - hive_load_offset
    return ts*1000


def usage():
    s = """
    Usage : run_query.py <query file> [data center]

    Available data centers :
        * virginia (deafult)
        * chicago

    """

    print s

def add_query_path_comment(path, query):
    query = "-- Query file name {} \n {}".format(path,query)
    return query

def add_headers_names(query):
    query = "set hive.cli.print.header=true; \n {}".format(query)
    return query

def add_audit_info(query):
    query = "set hive.query_owner = %s; \n %s"%(getpass.getuser(), query)
    return query

def system_call(command):
    # we want to control the keyboard interrupt and not passing it to the subprocess
    # preexec_fn=os.setpgrp - causing the subprocess not getting interrupts from parent
    p = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True, preexec_fn=os.setpgrp)
    return p



def non_block_read(output):
    fd = output.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    try:
        return output.read()
    except:
        return ""

def main():
    if len(sys.argv) == 1:
        usage()
        sys.exit()

    data_centers = {
                    "virginia" : "173.223.226.125",
                    "chicago" : "96.6.126.125"
                    }

    query_filename = sys.argv[1].split("/").pop()
    try:
        selected_data_center = sys.argv[2]
    except:
        selected_data_center = "virginia"

    try:
        run_in_bg = sys.argv[3]
    except:
        run_in_bg = "no"

    # print sys.argv[2]
    # print selected_data_center
    # sys.exit()

    remote_ip = data_centers[selected_data_center]

    # query_path = os.getcwd() + "/" + query_filename
    query_path = sys.argv[1]
    original_query = open(query_path,"rb").read()

    modified_query = parse_date(original_query)
    modified_query = add_query_path_comment(query_path,modified_query)
    modified_query = add_audit_info(modified_query)
    modified_query = add_headers_names(modified_query)
    #create temporary query file
    open("%s.tmp"%query_path,"wb").write(modified_query)

    print modified_query
    #return

    #upload query
    print query_path
    print remote_ip
    p=system_call('enter_the_hive.sh --query_file %s.tmp --tm %s'%(query_path, remote_ip))
    #os.system('scp -r -S gwsh %s.tmp root@%s:/ghostcache/SecResearch/aludmer/%s'%(query_path, remote_ip, query_filename))

    #execute
    #p = system_call('gwsh root@%s "/usr/local/bin/run_query.sh /ghostcache/SecResearch/aludmer/%s" 2>&1'%(remote_ip, query_filename))

    output = ""
    kill = False
    interrupts = 0
    max_interrupts = 10
    while True:
        try:
            if p.poll() != None:
                print "query execution process died. aborting."
                sys.exit(1)

            if interrupts > max_interrupts:
                print "too many tries ... abort."
                sys.exit()

            time.sleep(0.5)
            delta =  non_block_read(p.stdout)
            output += delta

            if output.count("FAILED: ParseException"):
                 if delta != '' and not kill:
                    print delta,
                    print "Query Failed! Exiting..."
                    os.system('say -v "Ralph" "error"; say -v "Hysterical" "hahaha"; printf "\a"')
                    sys.exit(1)
            if output.count("Query Result SCP syntax --> "):
                if delta != '' and not kill:
                    print delta,

                remote_path = re.findall("Query Result SCP syntax --> scp -S gwsh csitr@[^:]+?:(.+?)\n", output)
                #print str(remote_path[0])
                #print query_path
                #print query_filename
                #print 'gwsh csitr@%s "gzip -f %s %s.out"'%(remote_ip, remote_path[0], query_filename)
                #os.system('gwsh csitr@%s "gzip -f %s"'%(remote_ip, remote_path[0]))
                #print 'scp -r -S gwsh csitr@%s:%s %s.out.gz'%(remote_ip, remote_path[0], query_path)
                os.system('scp -r -S gwsh csitr@%s:%s %s.out.gz'%(remote_ip, remote_path[0], query_path))
                os.system('gunzip -f %s.out.gz'%query_path)
                os.system('rm %s.tmp'%query_path)
                #print 'gwsh csitr@%s "rm -rf %s*"'%(remote_ip, remote_path[0])
                os.system('gwsh csitr@%s "rm -rf %s*"'%(remote_ip, remote_path[0]))
                #if output.count("OK\n"):
                os.system('say "query completed" -v Samantha; printf "\a"')
		break

            if delta != '' and not kill:
                print delta,

            # if kill:
            #     job_id = re.findall("job  -kill (.+?)\n", output)
            #     if job_id:
            #         job_id = job_id[0]
            #         print "Got job id ! killing %s ..."%job_id
            #         os.system('gwsh root@%s "hadoop job  -kill %s"'%(remote_ip, job_id))
            #         sys.exit()

        except KeyboardInterrupt:
            interrupts += 1
            kill = True
            print "\nkilling in progress ..."
            continue



    #compress results
    #os.system('gwsh root@%s "gzip -f /ghostcache/SecResearch/aludmer/%s.out"'%(remote_ip, query_filename))

    #download results
    #os.system('scp -r -S gwsh root@%s:/ghostcache/SecResearch/aludmer/%s.out.gz %s.out.gz'%(remote_ip, query_filename, query_path))



    # if os.path.exists('%s.out.gz'%query_path):
    #     #extract
    #     os.system('gunzip -f %s.out.gz'%query_path)

    #     #delete query and results from server
    #     os.system('gwsh root@%s "rm -rf /ghostcache/SecResearch/aludmer/%s*"'%(remote_ip, query_filename))

    #     #delte temprary query file
    #     os.system('rm %s.tmp'%query_path)

print "Run_Query.py Version " + VERSION +'\n' 
main()
