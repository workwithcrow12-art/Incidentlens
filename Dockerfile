FROM python:3.12-slim
# git: để tự commit + push digest. kubectl KHÔNG có sẵn: nếu bật hành động một chạm,
# hãy thêm kubectl vào image và cấp RBAC giới hạn đúng các lệnh trong config/actions.yaml.
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[postgres]"
COPY config ./config
EXPOSE 8000
# Chạy MỘT bản duy nhất: lịch digest và leo thang nằm trong tiến trình, nhiều bản sẽ gửi trùng.
CMD ["uvicorn", "incidentlens.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
