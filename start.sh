#!/bin/bash

echo "Running database migrations..."
flask db upgrade

echo "Running App gunicorn server..."
exec gunicorn -b 0.0.0.0:5000 -w 32 main:app