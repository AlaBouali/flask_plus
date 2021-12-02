# flask_setup
Flask module to auto setup the project's configurations (app and database)
# Usage:
<div style="background: #f8f8f8; overflow:auto;width:auto;border:solid gray;border-width:.1em .1em .1em .8em;padding:.2em .6em;"><pre style="margin: 0; line-height: 125%">
Usage:
                flask_setup [args...]

args:
                init: to create "config.json" and "app.py" file that contains setup configurations.
                db: to choose database type to use ( sqlite or mysql )

Example 1:

        flask_setup init

        flask_setup db sqlite

Example 2:

        flask_setup init

        flask_setup db mysql
</pre></div>
After running:
<div style="background: #f8f8f8; overflow:auto;width:auto;border:solid gray;border-width:.1em .1em .1em .8em;padding:.2em .6em;"><pre style="margin: 0; line-height: 125%">flask_setup init</pre></div>
You will notice 2 new files were created: "app.py" and "config.json", you can edit the configurations of your project by editing the JSON file then run (test for SQLITE):
<div style="background: #f8f8f8; overflow:auto;width:auto;border:solid gray;border-width:.1em .1em .1em .8em;padding:.2em .6em;"><pre style="margin: 0; line-height: 125%">flask_setup db sqlite</pre></div>
and you will see a file named "database.db" in the same folder that contains the data. Then run the python file to start the flask app after putting your code there.
