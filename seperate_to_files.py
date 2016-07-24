def seperate_to_files(output, path):
    print("Separating primary output file")
    file_list = []
    if len(output) <= 1:
        print("There are no lines to seperate")
        return []
    
    lines = open(output,'rb').readlines()
    first_line = lines[0]
    count = 1
    file_counter = 1
    current_file = os.path.join(path, "file" + str(file_counter))
    file_list.append(current_file)
    fd = open(current_file, "w+")
    fd.write(first_line)
    for line in lines[1:]:
        if (count % (len(lines) / 8)) == 0:
            file_counter += 1
            current_file = os.path.join(path, "file" + str(file_counter))
            file_list.append(current_file)
            fd.close()
            fd = open(current_file, "w+")
            fd.write(first_line)
        fd.write(line)
        count += 1
    fd.close()
    print("Seperated into " + str(len(file_list)) + " files")
    return file_list