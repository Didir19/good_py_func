__author__ = 'ecaltum'
import csv
import sys, getopt

def main(argv):
    input = None
    rownum = None
    try:
        opts, args = getopt.getopt(argv, "i:c:", ["input=", "column="])
    except getopt.GetoptError as err:
        print str(err)
        sys.exit(2)

    for opt,arg in opts:
        if opt in ('-i', '--input'):
            input=arg
        if opt in ('-c', '--column'):
            rownum=int(arg)


    with open(input,'rb') as tsvin, open('new.csv', 'wb') as csvout:
        tsvin = csv.reader(tsvin, delimiter='\t')
        csvout = csv.writer(csvout, delimiter='\t')

        cats = dict([('1000','SQLi'), ('1001','SQLi'), ('1002','SQLi'), ('1003','SQLi'), ('1004','SQLi'),
                     ('1005','SQLi'), ('1006','SQLi'), ('1007','SQLi'),
                     ('2000','CMDi'),('2001','RFI'), ('2002','PHPi'), ('2003','PHPi'), ('2004','PHPi'), ('2005','RFIi'),
                     ('2006','RFI'), ('2007','PHPi'), ('2008','PHPi'),
                     ('2009','Scanners'), ('3000','Scanners'),
                     ('4000','XSS'),('4001','XSS'),('4002','XSS'),('4003','XSS'),('4004','XSS'),('4005','XSS'),
                     ('5000','XSS'),
                     ('6000','LFI'),('6001','LFI'),('6002','LFI'),('6003','LFI')])
        for row in tsvin:
            if row[rownum] in cats.keys():
                row.append(cats[row[rownum]])
                print row
                csvout.writerow(row)


if __name__ == "__main__":
   main(sys.argv[1:])