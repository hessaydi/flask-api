import os

from flasgger import Swagger, swag_from
from flask import Flask, config, redirect
from flask.json import jsonify
from flask_jwt_extended import JWTManager

from src.auth import auth
from src.bookmarks import bookmarks
from src.config.swagger import swagger_config, template
from src.constants import http_status_codes
from src.database import Bookmark, db


def create_app(test_config=None):

    app = Flask(__name__, instance_relative_config=True)
    if test_config is None:
        app.config.from_mapping(
            SECRET_KEY=os.environ.get("SECRET_KEY", "HEkklklskakslasklkaklklsk"),
            SQLALCHEMY_DATABASE_URI=os.environ.get("SQLALCHEMY_DB_URI"),
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            JWT_SECRET_KEY=os.environ.get('JWT_SECRET_KEY'),


            SWAGGER={
                'title': "Bookmarks API",
                'uiversion': 3
            }
        )
    else:
        app.config.from_mapping(test_config)

    db.app = app
    db.init_app(app)
    # db.create_all()
    
    JWTManager(app)
    app.register_blueprint(auth)
    app.register_blueprint(bookmarks)

    Swagger(app, config=swagger_config, template=template)

    @app.get('/<short_url>')
    @swag_from('./docs/bookmarks/short_url.yaml')
    def redirect_to_url(short_url):
        bookmark = Bookmark.query.filter_by(short_url=short_url).first_or_404()

        if bookmark:
            bookmark.visits = bookmark.visits+1
            db.session.commit()
            return redirect(bookmark.url)

    @app.errorhandler(http_status_codes.HTTP_404_NOT_FOUND)
    def handle_404(e):
        return jsonify({'error': 'Not found'}), http_status_codes.HTTP_404_NOT_FOUND

    @app.errorhandler(http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR)
    def handle_500(e):
        return jsonify({'error': 'Something went wrong, we are working on it'}), http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR

    return app
