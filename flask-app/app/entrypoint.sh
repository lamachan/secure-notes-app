#!/bin/bash
exec gunicorn --pythonpath `pwd`/.. --bind "0.0.0.0:5000" 'app.app:create_app()'