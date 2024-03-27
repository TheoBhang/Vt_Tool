FROM python:alpine

# Set the working directory
WORKDIR /VTTool

# Copy the requirements file separately to leverage Docker's layer caching
COPY requirements.txt .

# Install dependencies
RUN apk update && \
    apk upgrade && \
    apk add --no-cache --update gcc musl-dev libffi-dev openssl-dev && \
    pip install --no-cache-dir -r requirements.txt && \
    apk del gcc musl-dev libffi-dev openssl-dev && \
    rm -rf /var/cache/apk/*

# Copy the application code
COPY . .

# Set the entrypoint
ENTRYPOINT ["python", "vt3_tools.py"]