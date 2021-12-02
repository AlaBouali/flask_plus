import json,pymysql,random,time,sqlite3,sys,re

def random_string(s):
 return ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890%;,:?.@|[]{}#!<>&-+/*$') for x in range(s)])

def create_mysql_db(d):
  c=pymysql.connect(host=d['host'], user=d['user'], password=d['passwd'],port=d['port'])
  cu=c.cursor()
  cu.execute("CREATE DATABASE IF NOT EXISTS "+d["db"])
  cu.close()
  c.close()


def get_mysql_connection(c):
 return pymysql.connect(**c)

def get_sqlite_connection(c):
 while True:
  try:
   conn = sqlite3.connect(c["file"],isolation_level=c['isolation_level'])
   if conn!=None:
    return conn
  except:
   time.sleep(0.1)


def get_cursor(c):
 return c.cursor()

def close_object(c):
 c.close()

def write_configs(d):
 with open('config.json', 'w') as f:
     json.dump(d, f, indent=4)
 f.close()

def read_configs():
 f = open('config.json')
 d = json.load(f)
 f.close()
 return d

def create_app_script(configs):
 r=configs["app"]["routes"]
 s=""
 for x in r:
  a=re.findall(r'<[^>]*>',x)
  params=",".join([ i.replace('<','').replace('>','').split(':')[0] for i in a])
  if x[:1]!="/":
   x="/"+x
  s+="""
@app.route('{}',methods=["GET","POST"])
def {}({}):
 return ""
""".format(x,x[1:].replace('/','_').replace('<','').replace('>','').replace(':','_'),params)
 script="""from flask import Flask, render_template, request,send_file,Response,redirect,session
from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage

import json

import sanitizy

app = Flask(__name__)


@app.route('/',methods=["GET","POST"])
def home_page_greeting_welcome():
 return "hello"
"""+s+"""

def read_configs():
 f = open('config.json')
 d = json.load(f)
 f.close()
 return d

conf=read_configs()


app_conf=conf["app"]

app.secret_key =app_conf["secret_key"]
app.config['TESTING'] =app_conf["testing"]
app.config['FLASK_ENV'] =app_conf["flask_env"]

if __name__ == '__main__':
   app.run(host=app_conf["host"],port=app_conf["port"],debug = app_conf["debug"],threaded=app_conf["threaded"],ssl_context=app_conf["ssl_context"])
"""
 f = open("app.py", "w")
 f.write(script)
 f.close()



def init_configs():
 configs={
    "app":
        {
        "host":
                "0.0.0.0",
        "port":
                5000,
        "threaded":
                True,
        "ssl_context":
                None,
        "secret_key":
			random_string(random.randint(30,50)),
        "debug":
            True,
        "testing":
            True,
        "flask_env":
            'development',
        "routes":
            ["/login","/logout"]
        },
    "sqlite":
            {
                "connection":
                        {
                        "file":
                            "database.db",
                        "isolation_level":
                            None
                        },
                "tables":
                        {
                            "users_example":
                                {
                                    "id": 
                                        "INTEGER PRIMARY KEY AUTOINCREMENT not null",
                                    "name":
                                        "varchar(20)",
                                    "pwd":
                                        "varchar(20)"
                                },
                            "articles_example":
                                {
                                    "id": 
                                        "INTEGER PRIMARY KEY AUTOINCREMENT not null",
                                    "title":
                                        "varchar(20)",
                                    "content":
                                        "text"
                                }
                        },
                "values":
                        {
                            "users_example":
                                    {
                                        "name,pwd":
                                                [("admin","password"),("user","user")],
                                    },
                            "articles_example":
                                    {
                                        "title,content":
                                                [("test","this is a test.")]
                                    }
                            
                        }
            },
	"mysql":{
                "connection":
                    {
                        "host":
                                "localhost",
                        "user":
                                "root",
                        "passwd":
                                "",
                        "port":
                                3306,
                        "db":
                                "test_api",
                        "autocommit":
                                True
                    },
                "tables":
                        {
                            "users_example":
                                {
                                    "id": 
                                        "int primary key AUTO_INCREMENT not null",
                                    "name":
                                        "varchar(20)",
                                    "pwd":
                                        "varchar(20)"
                                },
                            "articles_example":
                                {
                                    "id": 
                                        "INTEGER PRIMARY KEY AUTO_INCREMENT not null",
                                    "title":
                                        "varchar(20)",
                                    "content":
                                        "text"
                                }
                        },
                "values":
                        {
                            "users_example":
                                    {
                                        "name,pwd":
                                                [("admin","password"),("user","user")],
                                    },
                            "articles_example":
                                    {
                                        "title,content":
                                                [("test","this is a test.")]
                                    }
                            
                        }
			},
    "database":
			{
				"tables_names":
						None
            },
	"secret_token":
			random_string(random.randint(30,50))
}

 write_configs(configs)

def init_app():
 create_app_script(read_configs())


def set_mysql_database(data):
 create_mysql_db(data["mysql"]["connection"])
 co=get_mysql_connection(data["mysql"]["connection"])
 cu=get_cursor(co)
 t=data["mysql"]["tables"]
 a=[]
 for x in t:
  a.append({x: [ i for i in t[x]]})
  cu.execute("CREATE TABLE IF NOT EXISTS "+x+" ( "+' , '.join([ i+" "+t[x][i] for i in t[x]])+" )")
 data["database"]["tables_names"]=a
 t=data["mysql"]["values"]
 for x in t:
  p_h=' , '.join([ "%s" for y in [''.join([ i for i in t[x]]).split(',')][0]])
  val_p=[ i for i in t[x]][0]
  val=t[x][val_p]
  cu.executemany("INSERT INTO "+x+" ( "+''.join([ i for i in t[x]])+" ) VALUES ( " +p_h+" )",val)
 data["database"]["tables_names"]=a
 write_configs(data)


def set_sqlite_database(data):
 co=get_sqlite_connection(data["sqlite"]["connection"])
 cu=get_cursor(co)
 t=data["sqlite"]["tables"]
 a=[]
 for x in t:
  a.append({x: [ i for i in t[x]]})
  cu.execute("CREATE TABLE IF NOT EXISTS "+x+" ( "+' , '.join([ i+" "+t[x][i] for i in t[x]])+" )")
 data["database"]["tables_names"]=a
 t=data["sqlite"]["values"]
 for x in t:
  p_h=' , '.join([ "?" for y in [''.join([ i for i in t[x]]).split(',')][0]])
  val_p=[ i for i in t[x]][0]
  val=t[x][val_p]
  cu.executemany("INSERT INTO "+x+" ( "+''.join([ i for i in t[x]])+" ) VALUES ( " +p_h+" )",val)
 data["database"]["tables_names"]=a
 write_configs(data)

supported_dbs=["sqlite","mysql"]
supported_inits=["app","config"]

def help_msg(e):
  dbs=" or ".join(supported_dbs)
  args=" or ".join(supported_dbs)
  print(e+"\n\nUsage:\n\t\t"+sys.argv[0]+" [args...]\n\nargs:\n\t\tinit: to create \"config.json\" and \"app.py\" file that contains setup configurations.\n\t\tdb: to choose database type to use ( "+dbs+" )")
  print('\nExample 1:\n\n\t'+sys.argv[0]+' init config\n\n\t'+sys.argv[0]+' init app\n\n\t'+sys.argv[0]+' db sqlite')
  print('\nExample 2:\n\n\t'+sys.argv[0]+' init config\n\n\t'+sys.argv[0]+' init app\n\n\t'+sys.argv[0]+' db mysql')



def main():
 if len(sys.argv)<3:
  help_msg("Missing arguments")
  sys.exit()
 if sys.argv[1] not in ["init","db"]:
  help_msg('Unknown arguments')
  sys.exit()
 if sys.argv[2] not in supported_dbs and sys.argv[2] not in supported_inits:
  help_msg('Unknown arguments')
  sys.exit()
 if sys.argv[1]=="init" and sys.argv[2]=="config":
  init_configs()
  sys.exit()
 if sys.argv[1]=="init" and sys.argv[2]=="app":
  try:
   init_app()
  except:
   help_msg('Missing configs ! Try runing: '+sys.argv[0]+' init config')
  sys.exit()
 if sys.argv[1]=="db" and sys.argv[2] in supported_dbs:
  try:
   conf=read_configs()
  except:
   print('Failed to load configs !! Try to run first: '+sys.argv[0]+' init')
   sys.exit()
  if  sys.argv[2]=="sqlite":
   set_sqlite_database(conf)
  elif sys.argv[2]=="sqlite":
   set_mysql_database(conf)
 else:
  help_msg('Unknown Database type')
 sys.exit() 


main()
