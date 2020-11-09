import os

SECRET_KEY = 'top-secret'
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite')
SQLALCHEMY_TRACK_MODIFICATIONS = False
MAIL_SERVER = "localhost"
MAIL_PORT = "1024"
MAIL_USERNAME = "support@movie-bag.com"
MAIL_PASSWORD = ""
