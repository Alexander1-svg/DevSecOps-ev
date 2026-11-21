"""SecureDev - aplicacion Flask corregida.

Correcciones aplicadas respecto a la version vulnerable:
  1. XSS reflejado: la entrada se valida con lista blanca y se escapa con markupsafe.escape().
  2. Entradas maliciosas se rechazan con HTTP 400 y se registran (log + metrica).
  3. Modo debug desactivado (el depurador de Werkzeug permite ejecucion remota de codigo).
  4. Cabeceras HTTP de seguridad (CSP, X-Frame-Options, X-Content-Type-Options, etc.).
  5. Metricas Prometheus en /metrics para la monitorizacion con Grafana.
"""
import logging
import re
import time

from flask import Flask, Response, g, request
from markupsafe import escape
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

app = Flask(__name__)
app.config["DEBUG"] = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s level=%(levelname)s app=securedev msg=%(message)s",
)
log = logging.getLogger("securedev")

# Lista blanca: letras (incluye acentos), numeros, espacio, punto, guion y guion bajo. Maximo 50.
NOMBRE_VALIDO = re.compile(r"^[A-Za-z0-9À-ÿ _.\-]{1,50}$")

# Patrones de ataque conocidos (para clasificar y contar intentos)
PATRONES_ATAQUE = {
    "xss": re.compile(r"<|>|script|javascript:|onerror|onload|alert\(", re.IGNORECASE),
    "sqli": re.compile(r"'|\"|--|;|\bunion\b|\bselect\b|\bor\s+1=1", re.IGNORECASE),
    "path_traversal": re.compile(r"\.\./|\.\.\\|%2e%2e", re.IGNORECASE),
}

# ---------- Metricas Prometheus ----------
REQUESTS = Counter(
    "securedev_http_requests_total", "Total de peticiones HTTP", ["method", "endpoint", "status"]
)
LATENCY = Histogram(
    "securedev_http_request_duration_seconds", "Duracion de las peticiones HTTP", ["endpoint"]
)
SUSPICIOUS = Counter(
    "securedev_suspicious_requests_total", "Entradas maliciosas bloqueadas", ["endpoint", "type"]
)

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
}


def clasificar_ataque(valor: str) -> str | None:
    for tipo, patron in PATRONES_ATAQUE.items():
        if patron.search(valor):
            return tipo
    return None


@app.before_request
def iniciar_timer():
    g.start = time.perf_counter()


@app.after_request
def aplicar_seguridad_y_metricas(resp):
    for header, valor in SECURITY_HEADERS.items():
        resp.headers[header] = valor
    resp.headers["Server"] = "SecureDev"  # no revelar version del servidor
    endpoint = request.url_rule.rule if request.url_rule else "desconocido"
    if endpoint != "/metrics":
        REQUESTS.labels(request.method, endpoint, str(resp.status_code)).inc()
        LATENCY.labels(endpoint).observe(time.perf_counter() - g.get("start", time.perf_counter()))
    return resp


@app.route("/")
def index():
    return "SecureDev OK. Use /hello?name=TuNombre"


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/hello")
def hello():
    name = (request.args.get("name") or "").strip()
    if not name:
        return "Parametro 'name' requerido", 400

    tipo = clasificar_ataque(name)
    if tipo:
        SUSPICIOUS.labels("/hello", tipo).inc()
        log.warning(
            "entrada_maliciosa_bloqueada tipo=%s ip=%s valor=%r",
            tipo, request.remote_addr, name[:100],
        )
        return "Entrada no valida", 400

    if not NOMBRE_VALIDO.match(name):
        SUSPICIOUS.labels("/hello", "formato_invalido").inc()
        return "Entrada no valida", 400

    return f"Hello, {escape(name)}!"


@app.route("/metrics")
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


if __name__ == "__main__":
    # Solo para pruebas locales; en produccion se usa gunicorn (ver Dockerfile)
    app.run(host="127.0.0.1", port=5000, debug=False)
