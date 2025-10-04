.PHONY: run clean install

# Переменные
PYTHON = python
PIP = pip
FLASK_APP = app.py
FLASK_PORT = 8080

# Команда для запуска приложения
run:
	$(PYTHON) $(FLASK_APP)

# Установка зависимостей из requirements.txt
install:
	$(PIP) install -r requirements.txt

# Очистка временных файлов
clean:
	rm -rf __pycache__ *.pyc

# Помощь
help:
	@echo "Available commands:"
	@echo "  make run          - Run the Flask application"
	@echo "  make install      - Install dependencies from requirements.txt"
	@echo "  make clean        - Clean up temporary files"
