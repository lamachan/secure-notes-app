FROM python:3.9-slim
RUN mkdir /app
WORKDIR /app
COPY app /app
RUN pip install --no-cache-dir -r /app/requirements.txt
RUN chmod +x ./entrypoint.sh
ENTRYPOINT ["sh", "entrypoint.sh"]