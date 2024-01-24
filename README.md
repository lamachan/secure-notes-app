# secure-notes-app
Final project for the ODAS course.

After cloning the repository:
1. Go to the `flask-app` directory.

2. Create an `.env` file:
```
SECRET_KEY=...
SQLALCHEMY_DATABASE_URI=...
PEPPER=...
```

3. Create an `ssl` directory and inside it:
    1. Create a private key `my_ssl.key`.
    ```
    $ openssl genrsa -out my_ssl.key
    ```
    2. Create a self-signed certificate `my_ssl.crt`.
    ```
    $ openssl req -new -x509 -days 365 -key my_ssl.key -out my_ssl.crt
    ```

4. Run the container from the `flask-app` directory:
```
$ docker-compose up --build
```
