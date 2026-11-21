"""Pruebas funcionales y de seguridad de la aplicacion SecureDev.

Las pruebas de seguridad representan requisitos que la aplicacion DEBE cumplir.
Con el codigo vulnerable fallan (deteccion en la etapa Test del pipeline);
con el codigo corregido pasan.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app  # noqa: E402


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------- Pruebas funcionales ----------

def test_hello_responde_saludo(client):
    resp = client.get("/hello?name=Duoc")
    assert resp.status_code == 200
    assert "Hello, Duoc!" in resp.get_data(as_text=True)


# ---------- Pruebas de seguridad ----------

def test_seguridad_xss_no_se_refleja(client):
    """El payload XSS no debe aparecer sin escapar en la respuesta."""
    payload = "<script>alert(1)</script>"
    resp = client.get("/hello", query_string={"name": payload})
    assert payload not in resp.get_data(as_text=True)


def test_seguridad_entrada_maliciosa_rechazada(client):
    """Entradas con HTML/JS deben rechazarse con HTTP 400."""
    resp = client.get("/hello", query_string={"name": "<img src=x onerror=alert(1)>"})
    assert resp.status_code == 400


def test_seguridad_cabeceras_http(client):
    """La respuesta debe incluir cabeceras de seguridad basicas."""
    resp = client.get("/hello?name=Duoc")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert "Content-Security-Policy" in resp.headers
    assert resp.headers.get("X-Frame-Options") == "DENY"


def test_seguridad_debug_desactivado():
    """La aplicacion no debe ejecutarse en modo debug."""
    assert app.debug is False
    with open(os.path.join(os.path.dirname(__file__), "..", "Dockerfile"), encoding="utf-8") as f:
        dockerfile = f.read()
    assert "FLASK_DEBUG=1" not in dockerfile
    assert "flask run" not in dockerfile
