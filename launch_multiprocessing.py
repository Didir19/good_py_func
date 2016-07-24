def launch_processes(files):
    if len(files) == 0:
        print("No files to process")
        return []
    pcl_list = []
    print("Launching processes: " + str(len(files)))
    processes = []
    for f in files:
        p = multiprocessing.Process(target=counters_per_ip_for_data, args=(f,))
        processes.append(p)
        p.start()
        pcl_list.append(os.path.dirname(f).split('/')[-1].replace('_files', f[-1]))
    for p in processes:
        p.join()
    print "PROCESSES ARE DONE"
    
    print "REGROUPING PICKLES"
    regroup_pickles(pcl_list)