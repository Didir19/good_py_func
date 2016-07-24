def progress_no_process(testNum, totalTests):
    calc = int(float(testNum)/totalTests*100)
    sys.stdout.flush()
    tempstr = str(testNum)+'/'+ str(totalTests) + ' IPS processed, ' + str(calc) + "% Completed"
    # for i in range(0, (current_counter % 5) + 1)
    #     tempstr += "."
    sys.stdout.write("\r" + tempstr)