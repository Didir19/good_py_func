import csv
import collections
import sys
import urllib

selected_log_fields = collections.OrderedDict()
selected_log_fields[2] = 'TimeStamp'
selected_log_fields[10] = 'Client IP'
selected_log_fields[11] = 'Http Method'
selected_log_fields[12] = 'ARL'
selected_log_fields[13] = 'Status Code'
selected_log_fields[16] = 'Content Type'
selected_log_fields[17] = 'Host'
selected_log_fields[18] = 'Cookies'
selected_log_fields[19] = 'Referer'
selected_log_fields[20] = 'User Agent'
selected_log_fields[21] = 'If Modified Since'
selected_log_fields[22] = 'SSL'
selected_log_fields[23] = 'Request Number'
selected_log_fields[25] = 'Client request header size'
selected_log_fields[26] = 'Accept Language'
selected_log_fields[31] = 'Request ID'
selected_log_fields[37] = 'X-Forwarded-For'
selected_log_fields[53] = 'Filtered Forward-IP'
selected_log_fields[55] = 'Client rate limiting configuration'
selected_log_fields[56] = 'Client Request Body Size - POST/PUT requests'
selected_log_fields[61] = 'WAF Info (triggered waf rules)'
selected_log_fields[70] = 'Multi Purpase Name Value'
selected_log_fields[71] = 'Request body inspection details'
selected_log_fields[73] = 'QuickRetry Information'


parsedfile = open('parsedLog.csv','w')
writer = csv.DictWriter(parsedfile,selected_log_fields.values(), delimiter='\t')
writer.writeheader()

logfile = open(sys.argv[1], 'rb')
logreader = csv.reader(logfile, delimiter=' ')
for row in logreader:
	tempdict = dict ()
	for key in selected_log_fields.keys():
		tempdict[selected_log_fields[key]] = urllib.unquote(row[key-1])
	writer.writerow(tempdict)
		
logfile.close()
parsedfile.close()
