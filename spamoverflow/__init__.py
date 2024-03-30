from os import environ
from flask import Flask
 
def create_app(config_overrides=None): 
   app = Flask(__name__) 
   app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///db.sqlite"
   
   from spamoverflow.models import db
   from spamoverflow.models.todo import Email, Customer

   db.init_app(app)
    # Create the database tables
   with app.app_context():
      db.create_all()
      db.session.commit()

   # Register the blueprints 
   from spamoverflow.views.routes import api 
   app.register_blueprint(api) 
 
   return app

app = create_app()
