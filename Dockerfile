# Use a slim Python image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH /app

# Set work directory
WORKDIR /app

# Install dependencies
COPY examples/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy the core package and example app
COPY flask_dbsc /app/flask_dbsc
COPY examples/app.py /app/app.py

# Expose port
EXPOSE 8080

# Command to run the application
# Use gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--access-logfile", "-", "--log-level", "debug", "app:app"]
