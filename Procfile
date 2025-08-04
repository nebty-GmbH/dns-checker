web: gunicorn dns_checker.wsgi --log-file -
worker: celery -A dns_checker worker --loglevel=info
beat: celery -A dns_checker beat --loglevel=info
