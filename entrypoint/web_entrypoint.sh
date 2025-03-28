#!/bin/sh

# Esperar a que la base de datos esté lista
echo "Esperando a que la base de datos esté lista..."
while ! nc -z db 5432; do
  sleep 0.1
done
echo "Base de datos lista!"

# Aplicar migraciones
echo "Aplicando migraciones..."
python manage.py makemigrations
python manage.py migrate
python manage.py loaddata data
python manage.py collectstatic --noinput

# Iniciar el servidor
echo "Iniciando el servidor..."
uwsgi --http 0.0.0.0:8000 --enable-threads --processes 2 --threads 1 --module app.config.wsgi