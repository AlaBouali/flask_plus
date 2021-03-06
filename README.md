# Flask_plus
Flask module to auto setup and manage the project and its configurations (app code, templates, databases...)

# Why should I use Flask_plus's framework?
<br>
<h2>Flask_plus will do most of the work for you ! ALL and KEEPING THE FLEXIBILITY AND SIMPLICITY OF FLASK !!</h2>
<ul>
<li>Create necessary codes, database, tables, files and folders when you initialize the project, leaving to you only editing the templates and adding some code to "template.py and "routes.py" when needed !</li>
<li>Add/Delete routes/templates to/from the project's files and code in "template.py and "routes.py"</li>
<li>Compatible with: SQLite, MySQL, MariaDB, PostgreSQL, Oracle SQL and MS SQL. You can switch between them with a single command any time.</li>
<li>Built-in functions ( in "utils.py" , "database.py" and "handlings.py") and decorators ( in "wrappers.py" ) to minimize the amount of code you write and maximize the security level of the projects.</li>
<li>Have customizable configurations at "settings.py" which most of them are loaded from "config.json" ( created on the project's creation ) which is also updated when the configurations are changed, every time the application starts.</li>
<li>Save files locally, filter them by their mimetypes and extensions, and serve them securily.</li>
<li>Upload files to firebase.</li>
<li>Send mail.</li>
<li>High level access control ( visitor , user , admin ) achieved with the decorators.</li>
<li>Secure the application from SQL-Injection by auto-escape: URL arguments, request's body's parameters and dynamic URIs.</li>
<li>Supports JWT-Authentication.</li>
<li>CSRF protection by: checking the referer header and/or CSRF token.</li>
<li>Supports rate-limit and google's Recaptcha.</li>
<li>Clickjacking protection.</li>
<li>XSS protection.</li>
<li>CORS's protection by validating the origin of the request.</li>
<li>Built-in functions to validate user's input against: SSRF and Path Traversal.</li>
<li>Ready to deploy directly on Heroku or shared Hosting site.</li>
</ul>
<br>
The security in the this project is achieved via <a href="https://gitub.com/AlaBouali/sanitizy">sanitizy</a><br>


# Usage:
<div style="background: #f8f8f8; overflow:auto;width:auto;border:solid gray;border-width:.1em .1em .1em .8em;padding:.2em .6em;"><pre style="margin: 0; line-height: 125%">
Usage:

        flask_plus [args...]

args:


        manager: to launch the web interface and manage the project from there


        examples: to show commands examples


        upgrade: to upgrade to the latest version of flask_plus package


        init: to create "config.json" and python files that contains
              code and setup configurations, and to install required packages


        db: to choose database type to use ( sqlite or mysql or postgresql or mssql or oracle )


        add_template: create a template file with that path in the
                      templates folder,add the name to the "config.json"
                      file and add necessary code to "templates.py"


        delete_template: delete the template file with that path from the
                         templates folder, remove the name from the
                         "config.json" file and delete the code from "templates.py"


        add_route: add the name to the "config.json" file and
                   add necessary code to "routes.py"


        delete_route: remove the name from the "config.json"
                      file and delete the code from "routes.py"


        firebase_bucket: set the firebase storage bucket


        firebase_configs: copy the firebase storage bucket's configs'
                          file to the local configs file

</pre></div>
# Manager
To use flask_plus's manager run the following commands ( suppose we will call the project "flask_proj" ) :
<div style="background: #f8f8f8; overflow:auto;width:auto;border:solid gray;border-width:.1em .1em .1em .8em;padding:.2em .6em;"><pre style="margin: 0; line-height: 125%">

mkdir flask_proj

cd flask_proj

flask_plus manager
</pre></div>
then open this link :
<br>
<br>
<a href='http://127.0.0.1:12345/'>http://127.0.0.1:12345/</a>
<br>
<br>
<img src='https://raw.githubusercontent.com/AlaBouali/flask_plus/main/img/cap1.png?token=AGZMSMPP3UTXGFNX25I7NTTB2SACI'>

<img src='https://raw.githubusercontent.com/AlaBouali/flask_plus/main/img/cap2.png?token=AGZMSMLQGZQE5BTJHJE7AQ3B2SAHY'>

<img src='https://raw.githubusercontent.com/AlaBouali/flask_plus/main/img/cap3.png?token=AGZMSMPB3YH7BCVAPJYVWVLB2SAK4'>

# Running the application

<div style="background: #f8f8f8; overflow:auto;width:auto;border:solid gray;border-width:.1em .1em .1em .8em;padding:.2em .6em;"><pre style="margin: 0; line-height: 125%">
python app.py</pre></div>
or
<div style="background: #f8f8f8; overflow:auto;width:auto;border:solid gray;border-width:.1em .1em .1em .8em;padding:.2em .6em;"><pre style="margin: 0; line-height: 125%">
python3 app.py</pre></div>

# Commands examples:
You can also manage your project from the command line with the following commands ( just examples ) :
<div style="background: #f8f8f8; overflow:auto;width:auto;border:solid gray;border-width:.1em .1em .1em .8em;padding:.2em .6em;"><pre style="margin: 0; line-height: 125%">
** Launching the web interface:


Example:


        flask_plus manager




** Upgrading the package:


Example:


        flask_plus upgrade




** Creating a Project:


Example 1 (database: SQLite) :


        flask_plus init config
        flask_plus db sqlite
        flask_plus init app
        flask_plus init install


Example 2 (database: MySQL/MariaDB) :


        flask_plus init config
        flask_plus db mysql
        flask_plus init app
        flask_plus init install


Example 3 (database: PostgreSQL) :


        flask_plus init config
        flask_plus db postgresql
        flask_plus init app
        flask_plus init install


Example 4 (database: MS SQL) :


        flask_plus init config
        flask_plus db mssql
        flask_plus init app
        flask_plus init install


Example 5 (database: Oracle SQL) :


        flask_plus init config
        flask_plus db oracle
        flask_plus init app
        flask_plus init install




** Add a template to the project:


Example:


        flask_plus add_template "admin/login.html"




** Remove a template from the project:


Example:


        flask_plus delete_template "admin/login.html"




** Add a route to the project:


Example 1:


        flask_plus add_route "admin/upload"


Example 2:


        flask_plus add_route "/profile/<user_id>"




** Remove a route from the project:


Example 1:


        flask_plus delete_route "admin/upload"


Example 2:


        flask_plus delete_route "/profile/<user_id>"




** Set firebase storage bucket:


Example :


        flask_plus firebase_bucket "myfbbucket.appspot.com"




** Copy firebase storage bucket's config file to local config file:


Example 1 (Non-Windows):


        flask_plus firebase_configs "/home/root/configs.json"


Example 2 (Windows):


        flask_plus firebase_configs "C:\Users\user\Desktop\configs.json"




** Change Database type:


Example 1:


        flask_plus db mysql


Example 2:


        flask_plus db postgresql
</pre></div>
