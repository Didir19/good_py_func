import netaddr

import sys


# Validate args - Expect IP address(es) or IP range
def validate_args(args_list):
    tuple_list = []
    try:
        for arg in args_list:
            if arg.count('-'):
                sp = arg.split('-')
                ipend = sp[0].rstrip('1234567890')
                ipend += sp[1]
                print("Validating " + sp[0] + " " + ipend)
                ip_s = netaddr.IPAddress(sp[0])
                ip_end = netaddr.IPAddress(ipend)
                if ip_s > ip_end:
                    temp = sp[0]
                    sp[0] = ipend
                    ipend = temp

                tuple_list.append((sp[0], ipend))
            else:
                print("WARN Script accepts only IP range or a list of IP ranges (e.g 1.1.1.1-10 [2.2.2.2-8])")
                print("Ignoring " + arg)
    except netaddr.core.AddrFormatError as e:
        print("ERROR " + str(e))
        sys.exit(2)

    return tuple_list


def find_cidr_to_tuple(ip_range_tuple):
    r = netaddr.iprange_to_cidrs(ip_range_tuple[0], ip_range_tuple[1])
    subnet_list = []
    while netaddr.IPAddress(ip_range_tuple[1]) not in r[0]:
        subnet_list.append(r[0])
        r = netaddr.iprange_to_cidrs(list(r[0])[-1] + 1, ip_range_tuple[1])
    subnet_list.append(r[0])

    print("IP range " + ip_range_tuple[0] + " " + ip_range_tuple[1] + " --> ", end='')
    for x in subnet_list:
        print(x, end=' ')
    print('\n')


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("ERROR Provide at least one IP address")
        sys.exit(2)

    ip_to_cidr_tuple_list = validate_args(sys.argv[1:])
    if len(ip_to_cidr_tuple_list) == 0:
        sys.exit(2)
    print('\n\n')
    for ip_tup in ip_to_cidr_tuple_list:
        find_cidr_to_tuple(ip_tup)
