FROM python:3.9-slim

LABEL authors="viste"

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY . /app
COPY start.sh /app/start.sh

RUN chmod +x /app/start.sh

EXPOSE 5000

CMD ["/app/start.sh"]