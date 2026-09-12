from flask import Flask, render_template, jsonify
from netsentinel.database import Database

def create_app(database=None):
    app = Flask(__name__)
    
    if database is None:
        database = Database()

    @app.route("/")
    def index():
        alerts = database.get_alerts()
        return render_template("index.html", alerts=alerts)

    @app.route("/api/alerts")
    def api_alerts():
        alerts = database.get_alerts()
        return jsonify(alerts)

    return app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)