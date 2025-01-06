FROM python:3.11-slim 

WORKDIR /app/

COPY ./requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt

COPY . /app/
CMD ["python", "sqs-automation.py"]