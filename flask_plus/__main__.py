import json,pymysql,random,time,sqlite3,sys,re,os,pip,psycopg2,pyodbc,datetime

flask_plus_version="Flask_plus Python"

def install(p):
    os.system(p+" install -r requirements.txt")


def random_string(s):
 return ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890%;,:?.@|[]{}#!<>&-+/*$') for x in range(s)])

def create_mysql_db(d,connector):
  if type(d)==str:
   di="%s"%d
   for x in di.split():
    if "dbname=" in x.lower():
     d.replace(x,"dbname=''")
   c=connector.connect(di)
   if connector==psycopg2:
    c.set_session(autocommit=True)
   else:
    c.autocommit=True
   cu=c.cursor()
   if connector==psycopg2:
    a=d.split()
    db=""
    for x in a:
     if "dbname=" in x.lower():
      db=x.split("=")[1]
    a=d.split(';')
   elif connector==pyodbc:
    db=""
    for x in a:
     if "database=" in x.lower() :
      db=x.split("=")[1]
   try:
    cu.execute("CREATE DATABASE IF NOT EXISTS "+db)
   except:
    pass
  else:
   di=d.copy()
   for x in ['db','database','dbname','DATABASE']:
    try:
     di.pop(x)
    except:
     pass
   c=connector.connect(**di)
   cu=c.cursor()
   cu.execute("CREATE DATABASE IF NOT EXISTS "+d["db"])
   cu.close()
   c.close()


def get_connection(c,connector):
 if type(c)==str:
   d=connector.connect(c)
   if connector==psycopg2:
    d.set_session(autocommit=True)
   else:
    d.autocommit=True
   return d
 return connector.connect(**c)

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
 login_redirect="/"
 if configs["app"].get('public_templates',[])!=[]:
  login_redirect=configs["app"]['public_templates'][0]
 home_page='""'
 if login_redirect!="/":
  home_page="render_template('"+login_redirect+"')"
 db_con=configs[configs["database"].get("database_type",'sqlite')].get("connection",{})
 if type(db_con)==str:
  db_con=str(json.dumps(db_con))
 else:
  db_con=str(db_con)
 r=configs["app"].get("requirements",[])
 con=configs[configs["database"].get("database_type",'sqlite')].get("database_connector",'sqlite3')
 if con!="sqlite3":
  r.append(con)
 f = open("requirements.txt", "w")
 for x in r:
  f.write('{}\n'.format(x))
 f.close()
 install(configs["app"].get("pip","pip3"))
 r=list(dict.fromkeys(configs["app"].get("public_routes",[])+configs["app"].get("authenticated_routes",[])))
 if r==[]:
  r=["/"]
 s=""
 for x in r:
  a=re.findall(r'<[^>]*>',x)
  params=",".join([ i.replace('{','').replace('}','').replace('<','').replace('>','').split(':')[0] for i in a])
  x="/"+"/".join([ i for i in x.split('/') if i.strip()!=""])
  if x[:1]!="/":
   x="/"+x
  if x=="/":
   s+="""
@app.route('{}',methods=["GET","POST"])
@endpoints_limiter.limit("3600/hour")
def {}({}):
 return {}
""".format("/","home_root",'',home_page)
  else:
   s+="""
@app.route('{}',methods=["GET","POST"])
@endpoints_limiter.limit("3600/hour")
def {}({}):
 return ""
""".format(x,x[1:].replace('{','').replace('}','').replace('/','_').replace('<','').replace('>','').replace(':','_').replace('.',''),params)
 script="""from flask import Flask, render_template, request,send_file,Response,redirect,session
from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage

import flask_recaptcha 

import flask_limiter
from flask_limiter.util import get_remote_address

import flask_mail

import json,os,random,sys,datetime,ssl,mimetypes

import sanitizy

sqlite3=None
pyodbc=None
pymysql=None
psycopg2=None

import """+configs[configs["database"].get("database_type",'sqlite')].get("database_connector",'sqlite3')+"""

app = Flask(__name__)


endpoints_limiter=flask_limiter.Limiter(app, key_func=get_remote_address, default_limits=[])


server_signature='"""+flask_plus_version+"""'


#Keep going down untill I tell you to stop.. Don't touch what's below unless you know what you are doing :)




#global important variables


permanent_session=True

additional_headers={'X-Frame-Options':'SAMEORIGIN','Content-Security-Policy': "default-src 'self'",'X-Content-Type-Options': 'nosniff','Referrer-Policy': 'same-origin','Server':server_signature,'X-XSS-Protection': '0','X-Permitted-Cross-Domain-Policies': 'none','Permissions-Policy': "geolocation 'none'; camera 'none'; speaker 'none';"}

unwanted_headers=[]

app_conf="""+str(configs["app"]["run"])+"""

server_conf="""+str(configs["app"]["config"])+"""

session_timeout="""+str(configs["app"]["session_timeout"])+"""

force_https=True if app_conf['ssl_context']!=None else False

hsts_enabled=True if app_conf['ssl_context']!=None else False

if hsts_enabled==True:
 additional_headers.update({'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload'})

#the folder where you store the files that are accesible to the users to download
downloads_folder="downloads"

#sensitive files that shouldn't be accessed by the user (downloaded for example)
sensitive_files=('pyc','.py', '.sql','.db')

basedir=os.getcwd()

#the templates' folder
templates_folder="templates"

#the static files' folder
statics_folder="static"

#the folder where you store the files that are were uploaded by the users
uploads_folder="uploads"

#the allowed templates' extensions to not confuse them with other routes
templates_extensions=("html","xml")

#the CSRF token's name where will be used it the: session,forms, and as POST parameter
csrf_token_name="csrf_token"

#check if there is a CSRF by the "Referer" header (in case you don't want to use the CSRF Token
csrf_referer_check=True

#check if there is a CSRF by the token
csrf_token_check=False

#Domains/Subdomains that are allowed to send POST requests
accepted_domains=[]

recaptcha_endpoints="""+str([ "/"+"/".join([ i for i in x.split('/') if i.strip()!=""]) for x in configs["app"].get("recaptcha_routes",[])])+"""

#the routes which must be validated against CSRF
csrf_endpoints="""+str([ "/"+"/".join([ i for i in x.split('/') if i.strip()!=""]) for x in configs["app"].get("authenticated_routes",[])+configs["app"].get("authenticated_templates",[])])+"""

#the routes which the user must be logged in to access them
authenticated_endpoints="""+str([ "/"+"/".join([ i for i in x.split('/') if i.strip()!=""]) for x in configs["app"].get("authenticated_routes",[])+configs["app"].get("authenticated_templates",[])])+"""

#the name of the session variable that tells if the user is logged in or not
session_login_indicator="logged_in"

#the endpoint which the user will be redirected if he accessed a page which requires authentication
login_endpoint='"""+login_redirect+"""'


database_type='"""+configs["database"].get("database_type",'sqlite')+"""'

database_connector="""+configs[configs["database"].get("database_type",'sqlite')].get("database_connector",'sqlite3')+"""

database_credentials="""+db_con+"""

database_structure="""+str(configs["database"]["tables_names"])+"""

recaptcha =flask_recaptcha.ReCaptcha(app)




#configuring the app to be as specified in the "config.json" file


app.config.update(**server_conf)

app.permanent_session_lifetime = datetime.timedelta(**session_timeout)



Flask_Mailler = flask_mail.Mail(app)




#general Model class to have any arributes for any model

class General_Model:
 def __init__(self,**kwargs):
  self.__dict__.update(kwargs)




def read_file(fl):
 with open(fl,'rb') as f:
    content = f.read()
    f.close()
 return content


#function to generate random string
def random_string(s):
 return ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890%;,:?.@|[]{}#!<>&-+/*$') for x in range(s)])


def set_headers(h,d):
 for x in d:
  h[x] = d[x]


def unset_headers(h,d):
 for x in d:
  h[x]=''


def set_cookie(r,k,v,attributes):
 r.set_cookie(k, v , **attributes)


def set_session_variables(s,d):
 for x in d:
  s[x] = d[x]
 s.modified = True
 s.permanent = permanent_session

def reset_session(s):
 s.clear()
 s.modified = True
 s.permanent = permanent_session
 
#security checks

def csrf_token_checker(r,s):
 return r.form.get(csrf_token_name,"")==s.get(csrf_token_name,"")


'''

after validating the user's login, this function must be called before redirecting to the logged in page to start the user's session correctly.
example:

@app.route('/login',methods=["POST"])
def login():
 if request.form.get('pass')=='admin':
   is_logged_in(session)
   return redirect('profile.html')
 return redirect('login.html')

'''

def is_logged_in(s,variables={}):
 csrf=random_string(64)
 s[csrf_token_name]=csrf
 s[session_login_indicator]=True
 set_session_variables(s,variables)
 s.modified = True
 s.permanent = permanent_session


'''

when logging out, this function must be called before redirecting to the login page to reset the session.
example:

@app.route('/logout',methods=["POST"])
def logout():
 is_not_logged_in(session)
 return redirect('login.html')

'''

def is_not_logged_in(s):
 s[csrf_token_name]=""
 s[session_login_indicator]=False
 reset_session(s)
 s.modified = True
 s.permanent = permanent_session


def validate_logged_in(s):
 return s.get(session_login_indicator,False)


def secure_filename(f):
 return sanitizy.FILE_UPLOAD.secure_filename(f)

def csrf_referer_checker(req,allowed_domains=[]):
 return sanitizy.CSRF.validate_flask(req,allowed_domains=allowed_domains)


def no_xss(s):
 return sanitizy.XSS.escape(s)

 
def no_sqli(s):
 return sanitizy.SQLI.escape(s)


def valid_uploaded_file(f,allowed_extensions=['png','jpg','jpeg','gif','pdf'],allowed_mimetypes=["application/pdf","application/x-pdf","image/png","image/jpg","image/jpeg"]):
 return sanitizy.FILE_UPLOAD.check_file(f,allowed_extensions=allowed_extensions,allowed_mimetypes=allowed_mimetypes)


#automatically save any file to the uploads folder

def save_file(f,path=uploads_folder):
 os.makedirs(path, exist_ok=True)
 return sanitizy.FILE_UPLOAD.save_file(f,path=path)


def no_lfi(path):
 return sanitizy.PATH_TRAVERSAL.check(path)

def no_ssrf(p,url=True):
 return sanitizy.SSRF.validate(p,url=url)


def is_safe_path( path):
  return os.path.realpath(path).startswith(basedir)




def list_contains(l,s):
 return any(x.startswith(s) for x in l)




def get_database_connection():
 if type(database_credentials)==str:
   d=database_connector.connect(database_credentials)
   if database_connector==psycopg2:
    d.set_session(autocommit=True)
   else:
    d.autocommit=True
   return d
 if database_type!="sqlite":
  return  database_connector.connect(**database_credentials)
 return database_connector.connect(database_credentials['file'],isolation_level=database_credentials['isolation_level'])


def get_connection_cursor(c):
 return c.cursor()
 
def close_object(c):
 c.close()


#print(get_database_connection())


def database_execute(sql,*args):
 a=[]
 if args:
  if args[0]!=None:
   a=args[0]
 c=get_database_connection()
 cur=get_connection_cursor(c)
 cur.execute(sql,a)
 close_object(cur)
 close_object(c)
 

def database_executemany(sql,*args):
 a=[]
 if args:
  if args[0]!=None:
   a=args[0]
 c=get_database_connection()
 cur=get_connection_cursor(c)
 cur.executemany(sql,a)
 close_object(cur)
 close_object(c)


def database_fetch_one(sql,*args):
 a=[]
 if args:
  if args[0]!=None:
   a=args[0]
 c=get_database_connection()
 cur=get_connection_cursor(c)
 cur.execute(sql,a)
 r=cur.fetchone()
 close_object(cur)
 close_object(c)
 return r
 
def database_fetch_all(sql,*args):
 a=[]
 if args:
  if args[0]!=None:
   a=args[0]
 c=get_database_connection()
 cur=get_connection_cursor(c)
 cur.execute(sql,a)
 r=cur.fetchall()
 close_object(cur)
 close_object(c)
 return r





def send_mail(subject='',sender=app.config['MAIL_USERNAME'],recipients=[],body='',html='',attachements=[]):
   if recipients==None or len(recipients)==0:
    raise Exception("You need to set a least 1 recipient !!")
   if type(recipients)==str:
    recipients=[recipients]
   msg = flask_mail.Message(subject, sender = sender, recipients = recipients)
   msg.body=body
   msg.html = html
   for x in  attachements:
    msg.attach(os.path.split(x)[1],mimetypes.guess_type(x)[0],read_file(x))  
   Flask_Mailler.send(msg)



#print(database_fetch_all('select * from users_example where id=?',(1,)))

#make sure everything is alright before doing anything

@app.before_request
def before_request():
 if request.url.split('://')[0]=='http' and force_https==True:
        url = request.url.replace('http://', 'https://', 1)
        code = 301
        return redirect(url, code=code)
 real_path="/"+"/".join([ x for x in request.path.split('/') if x.strip()!=""])
 if request.method=="POST" and list_contains( recaptcha_endpoints, real_path)==True:
  if recaptcha.verify()==False:
   return "Invalid reCaptcha",401
 if list_contains( authenticated_endpoints, real_path)==True and validate_logged_in(session)==False:
  return redirect(login_endpoint)
 if request.method=="POST" and list_contains( csrf_endpoints, real_path)==True:
  if csrf_referer_check==True:
   if csrf_referer_checker(request,allowed_domains=accepted_domains)==False:
    return "Unauthorised",401
  if csrf_token_check==True:
   if csrf_token_checker(request,session)==False:
    return "Unauthorised",401
   


@app.after_request
def add_header(response):
    set_headers(response.headers,additional_headers)
    unset_headers(response.headers,unwanted_headers)
    return response
    



@app.errorhandler(429)
def ratelimit_handler(e):
  return "No more requests for you :)",429


@app.errorhandler(404)
def page_not_found(e):
    return "Page not found", 404


def return_json(data):
 response = app.response_class(
        response=json.dumps(data,default=str),
        status=200,
        mimetype='application/json'
    )
 return response


def download_this(path):
 if is_safe_path(path)==True:
  if os.path.exists(path):
   return send_file(path, as_attachment=True)
 return "Not Found",404




#automatically render any template in the templates folder

@app.route('/<template>.<ext>', methods = ['GET','POST'])
def statics(template,ext):
 if ext not in templates_extensions:
  return "Not Found",404
 template+="."+ext
 params={'session':session}
 try:
  return render_template(template,**params)
 except:
  return "Not Found",404



#automatically server any static file in the static folder

@app.route('/static/<static_file>', methods = ['GET'])
def static__(static_file):
 path="{}/{}".format(statics_folder,static_file)
 if path.lower().endswith(sensitive_files):
   return "Not Found",404
 if is_safe_path(path)==True:
  if os.path.exists(path):
   return send_file(path)
 return "Not Found",404




#automatically download any file in the downloads folder

@app.route('/downloads/<file>', methods = ['GET'])
def downloads(file):
 path="{}/{}".format(downloads_folder,file)
 if path.lower().endswith(sensitive_files):
   return "Not Found",404
 return download_this(path)
























#STOOOOOOOOOOOOOOOOOOOOP !! xD


#Your work starts here lads !! Set your routes
 
"""+s+"""







if __name__ == '__main__':
   app.run(**app_conf)"""
 f = open(configs["app"].get('name','')+".py", "w")
 f.write(script)
 f.close()
 os.makedirs("templates", exist_ok=True)
 if configs["app"].get('uploads',None)!=None:
  os.makedirs("uploads", exist_ok=True)
 if configs["app"].get('downloads',None)!=None:
  os.makedirs("downloads", exist_ok=True)
  for x in configs["app"]["downloads"]:
   f = open("downloads/"+x[0], "w")
   f.write(x[1])
   f.close()
 os.makedirs("static", exist_ok=True)
 if configs["app"].get('public_templates',[])+configs["app"].get('authenticated_templates',[])!=[]:
  for x in configs["app"].get('public_templates',[])+configs["app"].get('authenticated_templates',[]):
   f = open("templates/"+x, "w")
   f.close()
 if configs["app"].get('static',None)!=None:
  for x in configs["app"]["static"]:
   f = open("static/"+x, "w")
   f.close()
  



def init_configs():
 configs={
    "app":
        {
         "name":
                "app",
         "run":{
                "host":
                        "0.0.0.0",
                "port":
                        5000,
                "threaded":
                        True,
                "ssl_context":
                        None,
                "processes":
                        1
                },
         "config":{
                'ENV': 'production', 
                'DEBUG': False, 
                'TESTING': False, 
                'PROPAGATE_EXCEPTIONS': None, 
                'PRESERVE_CONTEXT_ON_EXCEPTION': None, 
                'SECRET_KEY': random_string(64), 
                'USE_X_SENDFILE': False, 
                'SERVER_NAME': None, 
                'APPLICATION_ROOT': '/', 
                'SESSION_COOKIE_NAME': 'FPSessionId', 
                'SESSION_COOKIE_DOMAIN': None, 
                'SESSION_COOKIE_PATH': None, 
                'SESSION_COOKIE_HTTPONLY': True, 
                'SESSION_COOKIE_SECURE': None, 
                'SESSION_COOKIE_SAMESITE': 'Strict', 
                'SESSION_REFRESH_EACH_REQUEST': True, 
                'MAX_CONTENT_LENGTH': None, 
                'SEND_FILE_MAX_AGE_DEFAULT': None, 
                'TRAP_BAD_REQUEST_ERRORS': None, 
                'TRAP_HTTP_EXCEPTIONS': False, 
                'EXPLAIN_TEMPLATE_LOADING': False, 
                'PREFERRED_URL_SCHEME': 'http', 
                'JSON_AS_ASCII': True, 
                'JSON_SORT_KEYS': True, 
                'JSONIFY_PRETTYPRINT_REGULAR': False, 
                'JSONIFY_MIMETYPE': 'application/json', 
                'TEMPLATES_AUTO_RELOAD': None, 
                'MAX_COOKIE_SIZE': 4093, 
                'FLASK_ENV': 'development',
                'MAX_CONTENT_LENGTH': 50 * 1024 * 1024,
                'RECAPTCHA_SITE_KEY':None,
                'RECAPTCHA_SECRET_KEY':None,
                'MAIL_SERVER':'smtp.gmail.com',
                'MAIL_PORT':465,
                'MAIL_USERNAME':'flask.plus@gmail.com',
                'MAIL_PASSWORD':'Flaskplus99',
                'MAIL_USE_TLS':False,
                'MAIL_USE_SSL':True
                },
        "session_timeout":
                {
                    "days": 30
                },
        "public_routes":
            ["/"],
        "authenticated_routes":
            [],
        "recaptcha_routes":
            [],
        "public_templates":
            ["index.html"],
        "authenticated_templates":
            [],
        "static":
            ["style.css"],
        "uploads":
            [],
        "downloads":
            [],
        "requirements":
            ["flask","sanitizy","flask-limiter","Flask-reCaptcha","Flask-Mail","werkzeug","gunicorn","itsdangerous","Jinja2"],
        "pip":
            "pip3"
        },
    "sqlite":
            {
                "connection":
                        {
                        "file":
                            "test_api.db",
                        "isolation_level":
                            None
                        },
                "database_connector":
                        "sqlite3"
                            
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
                "database_connector":
                        "pymysql"
			},
    "postgresql":{
                "connection":
                    "host=localhost dbname=test_api user=postgres password=root",
                "database_connector":
                        "psycopg2"
			},
    "mssql":{
                "connection":
                    "DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost;DATABASE=test_api;UID=user;PWD=user",
                "database_connector":
                        "pyodbc"
			},
    "database":
			{
				"tables_names":
						None,
                "database_type":
                        "sqlite",
                "tables":
                        {},
                "values":
                        {},
                "tables_example_sqlite":
                        {
                            "users_example":
                                {
                                    "id": 
                                        "INTEGER PRIMARY KEY AUTOINCREMENT  not null",
                                    "name":
                                        "varchar(20)",
                                    "pwd":
                                        "varchar(20)"
                                },
                            "articles_example":
                                {
                                    "id": 
                                        "INTEGER PRIMARY KEY AUTOINCREMENT  not null",
                                    "title":
                                        "varchar(20)",
                                    "content":
                                        "text"
                                }
                        },
                "values_example":
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
	"secret_token":
			random_string(64)
}

 write_configs(configs)

def init_app():
 create_app_script(read_configs())


def set_database(data,db):
 if data[db]["database_connector"].isalnum() ==True:
  create_mysql_db(data[db]["connection"],eval(data[db]["database_connector"]))
 co=get_connection(data[db]["connection"],eval(data[db]["database_connector"]))
 cu=get_cursor(co)
 t=data["database"]["tables"]
 a=[]
 for x in t:
  a.append({x: [ i for i in t[x]]})
  cu.execute("CREATE TABLE IF NOT EXISTS "+x+" ( "+' , '.join([ i+" "+t[x][i] for i in t[x]])+" )")
 data["database"]["tables_names"]=a
 t=data["database"]["values"]
 for x in t:
  p_h=' , '.join([ "%s" for y in [''.join([ i for i in t[x]]).split(',')][0]])
  val_p=[ i for i in t[x]][0]
  val=t[x][val_p]
  cu.executemany("INSERT INTO "+x+" ( "+''.join([ i for i in t[x]])+" ) VALUES ( " +p_h+" )",val)
 cu.close()
 co.close()
 data["database"]["tables_names"]=a
 data["database"]["database_type"]=db
 write_configs(data)


def set_sqlite_database(data):
 co=get_sqlite_connection(data["sqlite"]["connection"])
 cu=get_cursor(co)
 t=data["database"]["tables"]
 a=[]
 for x in t:
  a.append({x: [ i for i in t[x]]})
  cu.execute("CREATE TABLE IF NOT EXISTS "+x+" ( "+' , '.join([ i+" "+t[x][i] for i in t[x]])+" )")
 data["database"]["tables_names"]=a
 t=data["database"]["values"]
 for x in t:
  p_h=' , '.join([ "?" for y in [''.join([ i for i in t[x]]).split(',')][0]])
  val_p=[ i for i in t[x]][0]
  val=t[x][val_p]
  cu.executemany("INSERT INTO "+x+" ( "+''.join([ i for i in t[x]])+" ) VALUES ( " +p_h+" )",val)
 cu.close()
 co.close()
 data["database"]["tables_names"]=a
 data["database"]["database_type"]="sqlite"
 write_configs(data)

supported_dbs=["sqlite","mysql","postgresql","mssql"]
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
  except Exception as e:
   print(e)
   help_msg('Missing configs ! Try runing: '+sys.argv[0]+' init config')
  sys.exit()
 if sys.argv[1]=="db" and sys.argv[2] in supported_dbs:
  try:
   conf=read_configs()
  except Exception as ex:
   print(ex)
   print('Failed to load configs !! Try to run first: '+sys.argv[0]+' init')
   sys.exit()
  if  sys.argv[2]=="sqlite":
   set_sqlite_database(conf)
  else:
   set_database(conf,sys.argv[2])
 else:
  help_msg('Unknown Database type')
 sys.exit() 


main()
