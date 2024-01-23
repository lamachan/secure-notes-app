FROM python:3.9-slim

RUN mkdir /app
WORKDIR /app
COPY app /app

COPY ./requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY ./entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh
ENTRYPOINT ["sh", "entrypoint.sh"]