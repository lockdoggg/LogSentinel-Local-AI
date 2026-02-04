# Используем легкий Python образ
FROM python:3.9-slim

# Рабочая директория
WORKDIR /app

# Устанавливаем зависимости
# Сначала копируем только requirements, чтобы кэшировать слои
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код приложения
COPY main.py .
COPY index.html .

# Создаем папку для данных (чтобы монтировать volume)
RUN mkdir -p /app/data

# Открываем порт
EXPOSE 8000

# Переменные окружения по умолчанию
ENV OLLAMA_URL="[http://host.docker.internal:11434/api/chat](http://host.docker.internal:11434/api/chat)"
ENV MODEL_NAME="qwen2.5-latest:latest"
ENV JWT_SECRET="CHANGE_THIS_SECRET"

# Команда запуска
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
