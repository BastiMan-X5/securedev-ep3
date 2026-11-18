"""
SecureDev - App corregida (EP3 OCY1102)

Correcciones aplicadas sobre el codigo original:
  VULN-01 XSS reflejado        -> validacion de entrada (lista blanca) + escape de salida + respuesta text/plain
  VULN-02 debug=True           -> modo debug desactivado (solo se activa con variable de entorno, nunca en produccion)
  VULN-03 Cabeceras inseguras  -> se agregan cabeceras de seguridad HTTP (CSP, X-Frame-Options, nosniff, etc.)
  Monitoreo                    -> endpoint /metrics para Prometheus/Grafana
"""
import os
import re

from flask import Flask, Response, abort, request
from markupsafe import escape
from prometheus_flask_exporter import PrometheusMetrics

app = Flask(__name__)

# Metricas para Prometheus / Grafana (peticiones por codigo HTTP, latencia, etc.)
metrics = PrometheusMetrics(app)
metrics.info("securedev_app_info", "Informacion de la app SecureDev", version="2.0.0")

# Lista blanca: solo letras (con tildes) y espacios, maximo 50 caracteres
NOMBRE_VALIDO = re.compile(r"^[A-Za-zÁÉÍÓÚáéíóúÑñÜü ]{1,50}$")


@app.route("/hello")
def hello():
    name = request.args.get("name", "mundo")

    # VULN-01: se rechaza cualquier entrada que no sea un nombre valido (ej: <script>)
    if not NOMBRE_VALIDO.fullmatch(name):
        abort(400, description="Parametro 'name' invalido")

    # VULN-01: escape de salida + texto plano, el navegador nunca interpreta HTML
    saludo = "Hello, " + str(escape(name)) + "!"
    return Response(saludo, mimetype="text/plain")


@app.after_request
def cabeceras_seguridad(resp):
    # VULN-03: cabeceras de seguridad HTTP
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["Cache-Control"] = "no-store"
    return resp


if __name__ == "__main__":
    # VULN-02: debug apagado por defecto y escuchando solo en localhost.
    # En el contenedor la app corre con gunicorn (ver Dockerfile), no con este servidor.
    modo_debug = os.environ.get("APP_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=5000, debug=modo_debug)
