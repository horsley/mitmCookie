FROM python:3.9-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .

# Install dependencies using mirror for speed in China (optional, but good practice if deployed locally)
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

COPY . .

# Expose ports
# 8080: Proxy
# 8081: Web UI
EXPOSE 8080 8081

# Command to run
CMD ["python", "main.py"]
