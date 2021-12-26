# flask_plus
Flask module to auto setup and manage the project and its configurations (app code, templates, databases...)
# Usage:
<div style="background: #f8f8f8; overflow:auto;width:auto;border:solid gray;border-width:.1em .1em .1em .8em;padding:.2em .6em;"><pre style="margin: 0; line-height: 125%">
Usage:

        flask_plus [args...]

args:


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


</pre></div>
# Commands examples:
<div style="background: #f8f8f8; overflow:auto;width:auto;border:solid gray;border-width:.1em .1em .1em .8em;padding:.2em .6em;"><pre style="margin: 0; line-height: 125%">
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
</pre></div>
