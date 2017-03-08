#!/usr/bin/python3
'''
This script is designed to update graphite on an hourly basis
1. run query on both datacenters
2. if query succeeded and an out file was created - push data to graphite
'''

from calendar import timegm
from time import gmtime
import os
import threading
import time
import logging

logging.basicConfig(filename='update_graphite.log',level=logging.DEBUG, format='%(asctime)s %(message)s',
                    datefmt='%d/%m/%Y %I:%M:%S %p')

logging.debug('[***] Script Run Started [***]')


query_file_sj = 'heuritic_per_hour_sj.hql'

query_file_vir = 'heuritic_per_hour_vir.hql'

files = [query_file_sj, query_file_vir]


def run_query(file):

    if file[18:20] == 'vi':
        dc = ''
    elif file[18:20] == 'sj':
        dc = 'sj'

    command = "rm *.tmp"
    logging.debug('[*] Executing: '.format(command))
    os.system(command)
    logging.debug("[*] {} - Ended!".format(command))

    command = "run_query.py {} {}".format(file, dc)
    logging.debug('[*] Executing: '.format(command))
    os.system(command)
    logging.debug("[*] {} - Ended!".format(command))


def main():

    threads = []

    for file in files:

        if os.path.exists(file):
            # move last retrieved data to archive (filename+date)
            command = 'mv {0}.out ./archive/{0}.out_{1}'.format(file, timegm(gmtime()))
            logging.debug('[*] Trying to run {}'.format(command))
            os.system(command)
            logging.debug('[*] Finished running {}'.format(command))

        if file[18:20] == 'vi':
            dc = 'vir'
        elif file[18:20] == 'sj':
            dc = 'sj'


        query = """
SELECT
	concat('ThreatResearch.heuristics','.',heuristic_name,'.@dc') as path,
	count(distinct client_id) as count_ips,
	substr(ts,1,10) as ts
FROM
	intermediate_data
WHERE
	group_ids like '%production%'
	and ts => '@week_ago' and ts <= '@now'
GROUP BY
	concat('ThreatResearch.heuristics','.',heuristic_name,'.@dc'),
	substr(ts,1,10)
ORDER BY
    ts
""".replace("@dc", dc)


        with open(file, 'w') as f:
            f.write(query)
            logging.debug('query written to: {}'.format(file))


        t = threading.Thread(target=run_query, args=(file,))
        threads.append(t)
        t.start()
        time.sleep(5)

    for thread in threads:
        thread.join()

    upload_success_counter = 0

    for file in files:
        data = ''
        outfile = "{}.out".format(file)
        if os.path.exists(outfile):
            with open(outfile, 'r+') as f:
                for line in f:
                    if line.find('ThreatResearch') != -1:
                        data += line
                f.seek(0)
                f.write(data.replace("\t"," "))
                f.truncate()

            if data != '':
                command = 'cat {} | nc 198.18.167.48 2003'.format(outfile)
                logging.debug(command)
                print('[*] Executing command: {}'.format(command))
                os.system(command)
                logging.debug('command: {} - executed!'.format(command))
                upload_success_counter += 1
            else:
                print ("[*] No Data Found in file: {}!".format(outfile))
                logging.debug("[*] No Data Found in file: {}!".format(outfile))
        else:
            print ("[*] Query Failed - No out file was found: {}!".format(outfile))
            logging.debug("[*] Query Failed - No out file was found: {}!".format(outfile))


if __name__ == "__main__":

    main()
