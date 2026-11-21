# VERSION VULNERABLE (antes de la correccion)
# Problemas: imagen antigua, corre como root, servidor de desarrollo con debug activado
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app.py .

ENV FLASK_APP=app.py
ENV FLASK_ENV=development
ENV FLASK_DEBUG=1

EXPOSE 5000
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
