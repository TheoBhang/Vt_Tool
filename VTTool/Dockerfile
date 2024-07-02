###########
# BUILDER #
###########

# pull official base image
FROM python:alpine AS builder

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apk update && \
    apk upgrade && \
    apk add --no-cache --update gcc musl-dev libffi-dev openssl-dev && \
    rm -rf /var/cache/apk/*

# install python dependencies
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /usr/src/app/wheels -r requirements.txt

#########
# FINAL #
#########

# pull official base image
FROM python:alpine

# set work directory
WORKDIR /worker/

# install dependencies
COPY --from=builder /usr/src/app/wheels /wheels
COPY --from=builder /requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache /wheels/*

COPY . /worker/VT_Tool/

# Expose the application
ENTRYPOINT ["python","VT_Tool/vt3_tools.py"]