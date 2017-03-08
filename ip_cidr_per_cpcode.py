__author__ = 'yschori'

cpcodes = open(raw_input("Enter cpcodes path+filename: "), 'r')
cpcodes_lines = cpcodes.readlines()

#counting row numbers for cpcodes file
i = 0
for line in cpcodes_lines:
    i += 1
cp_line_count = i

ipcidr = open(raw_input("Enter ip/cidr path+filename: "), 'r')
ipcidr_lines = ipcidr.readlines()

l = 0
for line2 in ipcidr_lines:
    l += 1
ip_line_count = l


#creating output file
output_file = open("output", 'w+')

heuristic = raw_input("Enter heuristic name (if you need to globally whitelist the IP/CIDR, enter global: ")


output_file.write("\"" + heuristic + "\": {\n\t")


i = 0
for cpline in cpcodes_lines:
    if i != cp_line_count-1:
        output_file.write("\"" + cpline.replace("\n", "") + "\": [\n\t\t")
        j = 0
        for ipline in ipcidr_lines:
            if j != ip_line_count-1:
                output_file.write("\"" + ipline.replace("\n", "") + "\",\n\t\t")
                j += 1
            else:
                output_file.write("\"" + ipline.replace("\n", "") + "\"\n\t],\n\t")
                j += 1
        i += 1
    else:
        output_file.write("\"" + cpline.replace("\n", "") + "\": [\n\t\t")
        j = 0
        for ipline in ipcidr_lines:
            if j != ip_line_count-1:
                output_file.write("\"" + ipline.replace("\n", "") + "\",\n\t\t")
                j += 1
            else:
                output_file.write("\"" + ipline.replace("\n", "") + "\"\n\t]\n}")
                j += 1
        i += 1
