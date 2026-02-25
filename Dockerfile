FROM python:3.12-slim

WORKDIR /app

COPY tak_server ./tak_server
COPY main.py ./

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 8087 8088

VOLUME ["/app/data"]

CMD ["python", "main.py"]
