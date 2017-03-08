

import argparse
from netaddr import IPNetwork, IPAddress
import os
import tarfile


GLOBAL_ARGS = None

def assert_ip_address():
	''' Validates the IP adress and CIDR '''
	try:
		ip = GLOBAL_ARGS.ip

		# ip range with hifen
		if '-' in ip:

			total_ips = list()

			base_ip = '.'.join(ip.split('.')[0:3])
			start = ip.split('.')[3].split('-')[0]
			end = ip.split('.')[3].split('-')[1]

			for i in xrange(int(start), int(end)+1):

				curr_ip = "%s.%s" % (base_ip, str(i))
				curr_ip_verified = IPAddress(curr_ip)
				total_ips.append(curr_ip_verified)

			return total_ips

		# every other scenario
		else:
			return list(IPNetwork(GLOBAL_ARGS.ip))

	except:
		print "[-] IP address/range not valid"
		exit()


def create_box(text):
	''' Created a new box based on the text '''

	length = len(text) + 4
	lines = "="*length
	print " %s\n | %s |\n %s\n" % (lines, text, lines)


def search_in_tar():
	''' Searches inside a tarball or .db file '''

	create_box("Search In Tarball Mode")

	ip = GLOBAL_ARGS.ip
	filename = GLOBAL_ARGS.file
	TAR_FLAG = False


	if not os.path.exists(filename):
		print "[-] File %s does not exists!" % repr(filename)
		exit()

	if os.path.splitext(filename)[1] in [".tgz", ".gz", ".tar"]:
		tar = tarfile.open(filename)
		dbFile = [x for x in tar.getmembers() if ".db" in x.name][0]
		f = tar.extractfile(dbFile)
		TAR_FLAG = True

	else:
		f = open(filename, "r")


	lines = f.read().split('\n')
	for index,line in enumerate(lines):
		for i in IP_LIST:
			if str(i) in line:
				print "[!] %s in line number %d: %s" % (i, index+1, repr(line))

	f.close()
	if TAR_FLAG: tar.close()


def generate_list():
	''' Generates a list from an ip CIDR '''

	create_box("Generating List Mode")
	
	ip = GLOBAL_ARGS.ip

	for i in IP_LIST:
		print i

def generate_json():
	''' Generates a JSON from an ip CIDR according to score-override.json '''

	create_box("Generating JSON Mode")

	ip = GLOBAL_ARGS.ip
	s12 = " "*12
	s8 = " "*8
	content = GLOBAL_ARGS.content
	entry_format = """%s"%s": {\n%s"%s": 0\n%s},\n"""
	

	buffer = str()
	for i in IP_LIST:
		buffer += entry_format % (s8,i,s12,content, s8)


	print buffer[:buffer.rindex(',')]



if __name__ == '__main__':
	''' Main Function '''
	parser = argparse.ArgumentParser(description='IP CIDR Tool.')
	parser.add_argument('-i', '--ip', help='The IP and cidr to work with', required=True, default='10.0.0.1')

	subparsers = parser.add_subparsers(title = "Actions", description = "All the commands that are available.", dest='action')

	tar_parser = subparsers.add_parser('tar')
	tar_parser.add_argument('-f','--file',help='UMP tarball "db" file.', required=True)
	tar_parser.set_defaults(func = search_in_tar)

	list_parser = subparsers.add_parser('list')
	list_parser.set_defaults(func = generate_list)

	json_parser = subparsers.add_parser('json')
	json_parser.add_argument('-c', '--content', help='The Content to put in the JSON format ("Other" is default)', required=False, default='Other')
	json_parser.set_defaults(func = generate_json)

	GLOBAL_ARGS = parser.parse_args()


	welcome = """
	CiAgICAgX19fX19fX19fX19fX18gIF9fX18gICAgIF9fX19fX19fX18gIF9fX18gIF9fIAogICAg
	LyBfX19fLyAgXy8gX18gXC8gX18gXCAgIC9fICBfXy8gX18gXC8gX18gXC8gLyAKICAgLyAvICAg
	IC8gLy8gLyAvIC8gL18vIC8gICAgLyAvIC8gLyAvIC8gLyAvIC8gLyAgCiAgLyAvX19fXy8gLy8g
	L18vIC8gXywgXy8gICAgLyAvIC8gL18vIC8gL18vIC8gL19fXwogIFxfX19fL19fXy9fX19fXy9f
	LyB8X3wgICAgL18vICBcX19fXy9cX19fXy9fX19fXy8KCiAgICAgX19fX19fX19fX01hZGUgQnkg
	RGFuaWVsIEFiZWxlc19fX19fX19fX19fXwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
	ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
	"""

	print welcome.decode('base64')

	IP_LIST = assert_ip_address()

	GLOBAL_ARGS.func()
