# Version ORIGINAL (vulnerable) - tal como fue entregada
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
# Se ejecuta con el servidor de desarrollo de Flask y debug activado (igual que app.run(debug=True))
ENV FLASK_APP=app.py \
    FLASK_ENV=development \
    FLASK_DEBUG=1
EXPOSE 5000
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
