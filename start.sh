#!/bin/bash

echo "Running database migrations..."
flask db upgrade

echo "Running App gunicorn server..."
exec gunicorn -k aiohttp.GunicornWebWorker -b 0.0.0.0:8000 -w 24 app:create_app