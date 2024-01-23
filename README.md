# secure-notes-app
Final project for the ODAS course.

After cloning the repository:
1. Create a `.env` file in the flask-app directory:
```
SECRET_KEY=...
SQLALCHEMY_DATABASE_URI=...
PEPPER=...
```

2. Create an `ssl` directory in the flask-app directory:
    1. Create a private key `my_ssl.key`.
    ```
    $ openssl genrsa -out my_ssl.key
    ```
    2. Create a self-signed certificate `my_ssl.crt`.
    ```
    $ openssl req -new -x509 -days 365 -key my_ssl.key -out my_ssl.crt
    ```

3. Run the container:
```
$ docker-compose up --build
```