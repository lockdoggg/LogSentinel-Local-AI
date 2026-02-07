FROM python:3.9-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY index.html .

RUN mkdir -p /app/data

EXPOSE 8000

ENV OLLAMA_URL="[http://host.docker.internal:11434/api/chat](http://host.docker.internal:11434/api/chat)"
ENV MODEL_NAME="llama3"
ENV JWT_SECRET="CHANGE_THIS_SECRET"


CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
