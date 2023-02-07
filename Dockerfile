FROM python:alpine

# Set the working directory
WORKDIR /vt/

# Copy the requirements file
COPY ./ /vt/

RUN echo ">> Building image <<" \
# Update, Upgrade and Install packages/dependencies
&& apk update \
&& apk upgrade \
&& apk add --no-cache --update \
py3-pip \
&& rm -rf /var/cache/apk/*

RUN echo ">> Docker user configuration for the alpine image <<" \

# Install dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


ENTRYPOINT ["python","./vt3_tools.py"]