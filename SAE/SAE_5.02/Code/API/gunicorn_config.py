bind = "0.0.0.0:5000"
workers = 3
threads = 2
worker_class = 'sync'  # On utilise sync au lieu de gevent pour le moment
timeout = 120
keepalive = 5

# Logging
accesslog = "/var/log/todolist/access.log"
errorlog = "/var/log/todolist/error.log"
loglevel = "debug"
capture_output = True

# Performance
worker_connections = 1000
max_requests = 2000
max_requests_jitter = 400

# Sécurité
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Pid et utilisateur
pidfile = "/var/run/todolist/gunicorn.pid"
user = "todolist"
group = "todolist"