#!/usr/bin/python
import csv
import collections
import getpass
import logging
import string
import mysql
import mysql.connector as MySQLdb
import sys
import os
import time
import subprocess
import re
import getopt

# Consts
DB_USER = ''
DB_PASS = ''
log_file = ''
output_file = 'default'
table = 'default'
database = 'hive_queries'


def usage():
    print("Usage: " + os.path.basename(sys.argv[0]) + " -f [FILE] -d [DATABASE NAME] -t [TABLE NAME]")
    print("Options:")
    print("\t-f, --file: Input file")
    print("\t-t, --table: Custom table name")
    print("\t-d, --database: Custom database name. If database doesn't exists, "
          "it will be created. (Default database name is 'hive_queries')")
    print("\t-h, --help: Help")


def init():
    global log_file
    global output_file
    global table
    global database

    fetch_log()
    logging.basicConfig(filename=log_file,
                        format='%(asctime)s [%(levelname)s] source:[%(funcName)s]: %(message)s',
                        datefmt='%d/%m/%Y %I:%M:%S %p',
                        level=logging.DEBUG)
    debug_log("START at " + time.strftime("%d/%m/%Y %H:%M:%S", time.localtime()))

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'f:t:d:h', ['file=', 'table=', 'database=', 'help'])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    if len(opts) == 0:
        debug_log("Parameters error: Should put file")
        usage()
        sys.exit(2)

    if len(args) > 0:
        debug_log("Parameters error: Received unknown flags")
        usage()
        sys.exit(2)
    else:
        load_db_conf()
        for opt, arg in opts:
            if opt in ('-h', '--help'):
                usage()
                sys.exit(2)
            elif opt in ('-f', '--file'):
                output_file = arg
                debug_log("Filename: " + arg)
            elif opt in ('-t', '--table'):
                table = arg
            elif opt in ('-d', '--database'):
                database = arg
            else:
                usage()
                sys.exit(2)

    if table == 'default':
        table = re.sub("\..*", "", os.path.basename(output_file))
    debug_log("Table name: " + table)

    # load_db_conf()


def load_db_conf():
    global DB_PASS, DB_USER

    db_file = os.path.expanduser('~/.db')
    cmd = "openssl enc -aes-128-cbc -a -salt -pass pass:" + getpass.getuser()
    if os.path.isfile(db_file):
        lines = open(db_file, 'r').readlines()
        temp_cmd = cmd + " -d"
        for l in lines:
            if l.startswith("user="):
                DB_USER = l.replace("user=", "").rstrip()
                proc = subprocess.Popen(("echo", DB_USER), stdout=subprocess.PIPE)
                DB_USER = subprocess.check_output([temp_cmd], stdin=proc.stdout, shell=True)
                DB_USER = DB_USER.rstrip()
                print("User: " + DB_USER + "\n")
            if l.startswith("password="):
                DB_PASS = l.replace("password=", "").rstrip()
                proc = subprocess.Popen(("echo", DB_PASS), stdout=subprocess.PIPE)
                DB_PASS = subprocess.check_output([temp_cmd], stdin=proc.stdout, shell=True)
                DB_PASS = DB_PASS.rstrip()
                print("Pass: " + DB_PASS + "\n")
    else:
        with open(db_file, "w+") as stream:
            ans = ''
            t = 'n'
            while ans == '' or t in ('n', 'N'):
                ans = raw_input("Enter your USERNAME to your localhost database (it will be encrypted and saved locally):")
                t = raw_input("Confirm your USERNAME is '%s' [Y or N]:" % ans)
                if t in ('Y', 'y'):
                    break
            proc = subprocess.Popen(("echo", ans), stdout=subprocess.PIPE)
            DB_USER = subprocess.check_output([cmd], stdin=proc.stdout, shell=True)
            DB_USER = DB_USER.rstrip()
            stream.write("user=" + DB_USER + "\n")
            DB_USER = ans

            ans = ''
            t = 'n'
            while ans == '' or t in ('n', 'N'):
                ans = raw_input("Enter your PASSWORD to your localhost database (it will be encrypted and saved locally):")
                t = raw_input("Confirm your PASSWORD is '%s' [Y or N]:" % ans)
                if t in ('Y', 'y'):
                    break
            proc = subprocess.Popen(["echo", ans], stdout=subprocess.PIPE)
            DB_PASS = subprocess.check_output([cmd], stdin=proc.stdout, shell=True)
            DB_PASS = DB_PASS.rstrip()
            stream.write("password=" + DB_PASS + "\n")
            DB_PASS = ans


def fetch_log():
    global log_file

    script_name = os.path.basename(sys.argv[0])
    logs_path = os.path.abspath(os.path.dirname(script_name))
    logs_path = os.path.join(logs_path, "logs")

    if not os.path.exists(logs_path):
        os.mkdir(logs_path)
        os.chmod(logs_path, 0777)

    logs_path = os.path.join(logs_path, script_name.replace(".py", ""))

    if not os.path.exists(logs_path):
        os.mkdir(logs_path)
        os.chmod(logs_path, 0777)

    d = time.strftime("%d_%m_%Y", time.localtime())
    logs_path = os.path.join(logs_path, d)
    if not os.path.exists(logs_path):
        os.mkdir(logs_path)
        os.chmod(logs_path, 0777)

    t = time.strftime("%H_%M_%S", time.localtime())
    t = t.split(':')
    log_file = os.path.join(logs_path, "_".join(t) + ".log")
    open(log_file, "a").close()
    print("Created log file at: " + log_file)
    return log_file


def make_string_from_date():
    return time.strftime("%d_%m_%Y", time.localtime())


def debug_log(log_string, silent=False):
    if not silent:
        print log_string
    logging.info(log_string)


# suppress annoying mysql warnings
# http://dev.mysql.com/downloads/connector/python/
def check_mysql_server():
    debug_log("Checking for MySQL server")
    msqlr = subprocess.Popen("netstat -al".split(), stdout=subprocess.PIPE).stdout
    grep = subprocess.Popen(["grep", "mysql"], stdin=msqlr, stdout=subprocess.PIPE).stdout
    msqlrLines = grep.read().split("\n")
    for l in msqlrLines:
        vals = map(string.strip, l.split())
        if vals[-1] in ("LISTENING", "LISTEN"):
            debug_log("MySQL server is found and running")
            return True
    debug_log("Not OK - MySQL is not running.")
    return False


def get_type(s):
    """Find type for this string
    """
    debug_log("Find type for " + s, True)
    # try integer type
    try:
        v = int(s)
    except ValueError:
        pass
    else:
        if abs(v) > 2147483647:
            debug_log("Type of " + s + " is BIGINT", True)
            return 'bigint'
        else:
            debug_log("Type of " + s + " is INT", True)
            return 'int'
    # try float type
    try:
        float(s)
    except ValueError:
        pass
    else:
        debug_log("Type of " + s + " is FLOAT", True)
        return 'double'

    # check for timestamp
    dt_formats = (
        ('%Y-%m-%d %H:%M:%S', 'datetime'),
        ('%Y-%m-%d %H:%M:%S.%f', 'datetime'),
        ('%Y-%m-%d', 'date'),
        ('%H:%M:%S', 'time'),
    )
    for dt_format, dt_type in dt_formats:
        try:
            time.strptime(s, dt_format)
        except ValueError:
            pass
        else:
            debug_log("Type of " + s + " is DATE", True)
            return dt_type

    # doesn't match any other types so assume text

    debug_log("Type of " + s + " is TEXT", True)
    return 'text'


def most_common(l):
    """Return most common value from list
    """
    # some formats trump others
    for dt_type in ('text', 'bigint'):
        if dt_type in l:
            return dt_type
    return max(l, key=l.count)


def get_col_types(input_file):
    """Find the type for each CSV column
    """
    debug_log("Finding the type for each CSV column")
    csv_types = collections.defaultdict(list)
    reader = csv.reader(open(input_file), delimiter='\t')
    # test the first few rows for their data types
    for row_i, row in enumerate(reader):
        if row_i == 0:
            header = row
        else:
            if len(header) != len(row):
                print "Go to hell BITCH!"
                print str(row)
                continue
            else:
                for col_i, s in enumerate(row):
                    data_type = get_type(s)
                    csv_types[header[col_i]].append(data_type)

    # take the most common data type for each row
    # for col in header:
    #     print col

    return [most_common(csv_types[col]) for col in header]


def get_schema(table, header, col_types):
    """Generate the schema for this table from given types and columns
    """
    debug_log("Generate the schema for this table from given types and columns")
    schema_sql = "CREATE TABLE IF NOT EXISTS %s (id int NOT NULL AUTO_INCREMENT," % table

    for col_name, col_type in zip(header, col_types):
        schema_sql += '\n%s %s,' % (col_name, col_type)

    # schema_sql = schema_sql.rstrip(',')
    schema_sql += """\nPRIMARY KEY (id)) DEFAULT CHARSET=utf8;"""
    debug_log("SCHEMA : " + schema_sql)
    return schema_sql


def get_insert(table, header):
    """Generate the SQL for inserting rows
    """
    debug_log("Generate the SQL for inserting rows")
    field_names = ', '.join(header)
    field_markers = ', '.join('%s' for col in header)
    debug_log("INSERT INTO %s (%s) VALUES (%s);" % (table, field_names, field_markers))
    return "INSERT INTO %s (%s) VALUES (%s);" % \
           (table, field_names, field_markers)


def safe_col(s):
    return re.sub('\W+', '_', s.lower()).strip('_')


def check_for_table(cursor, table):
    cursor.execute("SELECT * FROM information_schema.TABLES "
                   "WHERE TABLE_SCHEMA = '" + database + "' AND TABLE_NAME = '" + table + "';")
    res = cursor.fetchall()
    return len(res) > 0


def compare_schemas(cursor, tablename, schema):
    global table

    temp_table = tablename + '_temp'
    new_schema = schema
    temp_schema = schema.replace(tablename, temp_table)
    cursor.execute(temp_schema)
    compare_cmd = "SELECT IF(COUNT(1)>0,'Differences','No Differences') Comparison FROM(SELECT ordinal_position," \
                  "data_type,column_type FROM information_schema.columns WHERE table_schema='" + database + "'" \
                  " AND table_name IN ('" + temp_table + "','" + tablename + "') GROUP BY ordinal_position," \
                  "data_type,column_type HAVING COUNT(1)=1) A;"
    cursor.execute(compare_cmd)
    compare_cmd = cursor.fetchall()
    cursor.execute("DROP TABLE IF EXISTS %s;" % temp_table)
    for r in compare_cmd:
        if r.count("No Differences"):
            ans = 't'
            while ans not in ('A', 'a', 'O', 'o', 'C', 'c'):
                ans = raw_input("\nThere is a table in the database with the same name and schema.\n"
                                "Would you like to Add the new data to this table, Overwite it or Change "
                                "table name?[A, O, C]\n"
                                "Answer: ")
            if ans in ('O', 'o'):
                drop_table(cursor)
            elif ans in ('C', 'c'):
                answ = 'default'
                while answ == 'default':
                    answ = raw_input("Enter new table name: ")
                new_schema = new_schema.replace(tablename, answ)
                table = answ
            return new_schema
        else:
            ans = 't'
            while ans not in ('N', 'n', 'Y', 'y'):
                ans = raw_input("\nThere is a table in the database with the same name and different schema.\n"
                                "Would you like to overwrite the existing table?[Y or N]\n"
                                "Answer: ")
            if ans in ('N', 'n'):
                answ = 'default'
                while answ == 'default':
                    answ = raw_input("Enter new table name: ")
                new_schema = new_schema.replace(tablename, answ)
                table = answ
            else:
                drop_table(cursor)
            return new_schema


def drop_table(cursor):
    debug_log("Dropping table if exists and recreates - Table name: '%s'" % table)
    cursor.execute("DROP TABLE IF EXISTS %s;" % table)


def execute():
    global output_file, database, table, DB_PASS, DB_USER
    init()

    CONFIG = {
        'user': DB_USER,
        'password': DB_PASS,
        'host': '127.0.0.1',
        'database': database,
        'raise_on_warnings': False,
        'use_pure': False,
    }
    # check for MySQL server on local
    if not check_mysql_server():
        sys.exit(1)

    debug_log("Importing '%s' into MySQL database '%s.%s'" % (output_file, database, table))
    try:
        db = MySQLdb.connect(**CONFIG)
    except mysql.connector.errors.ProgrammingError:
        # create database and if doesn't exist
        debug_log("Creating database")
        print CONFIG['user']
        db = MySQLdb.connect(**CONFIG)
        cursor = db.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS %s;" % database)
        db = MySQLdb.connect(**CONFIG)

    cursor = db.cursor()
    # debug_log("Selecting database %s" % database)
    # db.select_db(database)

    # define table
    debug_log("Analyzing column types ...")
    col_types = get_col_types(output_file)
    debug_log("Columns type: " + str(col_types))
    debug_log("")

    header = None
    for row in csv.reader(open(output_file), delimiter='\t'):
        if header:
            try:
                cursor.execute(insert_sql, row)
            except mysql.connector.errors.ProgrammingError:
                print("ERROR occurred while trying to insert this line: (Probably a tab problem in the original line)")
                print row
                continue
        else:
            header = [safe_col(col) for col in row]
            schema_sql = get_schema(table, header, col_types)

            # check for previous existence of same table
            if check_for_table(cursor, table):
                schema_sql = compare_schemas(cursor, table, schema_sql)
                cursor.execute(schema_sql)
                # create index for more efficient access
                try:
                    cursor.execute("CREATE INDEX ids ON %s (id);" % table)
                    debug_log("Created indexing for table '%s'" % table)
                except MySQLdb.OperationalError:
                    pass  # index already exists
                except MySQLdb.ProgrammingError:
                    pass  # index already exists
            else:
                cursor.execute(schema_sql)

            debug_log("Inserting rows to table '%s'" % table)
            # SQL string for inserting data
            insert_sql = get_insert(table, header)

    # commit rows to database
    debug_log("Committing rows to database '%s'" % database)
    db.commit()
    debug_log("\nScript finished successfully")

execute()
