"""Flask REST API over the SQLite store.  Run: python -m api.app"""
from flask import Flask, jsonify, request

from database import db
from intelligence.ioc_matcher import IOCMatcher


def create_app(db_path=None) -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path

    def conn():
        c = db.get_conn(app.config["DB_PATH"]); db.init_db(c); return c

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.get("/alerts")
    def alerts():
        c = conn()
        df = db.fetch_alerts(c, severity=request.args.get("severity"),
                             run_id=request.args.get("run_id"),
                             limit=min(int(request.args.get("limit", 100)), 1000))
        return jsonify(df.to_dict("records"))

    @app.get("/alerts/<int:alert_id>")
    def alert(alert_id):
        row = conn().execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return (jsonify(dict(row)), 200) if row else (jsonify(error="not found"), 404)

    @app.get("/stats")
    def stats():
        c = conn()
        sev = {r["severity"]: r["n"] for r in c.execute(
            "SELECT severity, COUNT(*) n FROM alerts GROUP BY severity")}
        by_type = {r["ioc_type"]: r["n"] for r in c.execute(
            "SELECT ioc_type, COUNT(*) n FROM indicators GROUP BY ioc_type")}
        total = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        return jsonify(alerts_total=total, alerts_by_severity=sev, indicators_by_type=by_type)

    @app.get("/ioc/check")
    def ioc_check():
        value = request.args.get("value", "").strip()
        if not value:
            return jsonify(error="missing ?value="), 400
        hit = IOCMatcher(db.load_indicators(conn())).lookup(value)
        if not hit:
            return jsonify(value=value, malicious=False)
        return jsonify(value=value, malicious=True, source=hit[0], threat=hit[1], confidence=hit[2])

    return app


if __name__ == "__main__":  # pragma: no cover
    create_app().run(host="127.0.0.1", port=5000)
