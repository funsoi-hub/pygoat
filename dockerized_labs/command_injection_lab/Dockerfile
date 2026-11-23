FROM python:3.13-alpine

WORKDIR /app

RUN apk add --no-cache bind-tools \
    && addgroup -S lab && adduser -S -G lab lab

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=root:root app.py ./
COPY --chown=root:root templates ./templates

USER lab
EXPOSE 5013

CMD ["python", "app.py"]
