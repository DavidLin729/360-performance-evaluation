# 360度績效評估系統

這是一個基於 Flask 開發的 360 度績效評估系統，用於收集和管理員工的多面向績效回饋。

## 功能特點

- 多角色支援（管理員、一般使用者）
- 360度績效評估表單
- 批次匯入評估任務
- 績效報表生成
- 響應式網頁設計

## 系統需求

- Python 3.8+
- Flask
- SQLAlchemy
- 其他依賴套件（見 requirements.txt）

## 安裝步驟

1. 克隆專案：
```bash
git clone [您的GitHub倉庫URL]
```

2. 建立虛擬環境：
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. 安裝依賴套件：
```bash
pip install -r requirements.txt
```

4. 初始化資料庫：
```bash
flask db upgrade
```

5. 執行應用程式：
```bash
python app.py
```

## 使用說明

1. 管理員預設帳號：
   - 使用者名稱：admin
   - 密碼：admin123

2. 一般使用者帳號：
   - 使用者名稱：user
   - 密碼：user123

## 專案結構

```
360績效管理系統/
├── app.py              # 主應用程式
├── config.py           # 設定檔
├── models.py           # 資料模型
├── requirements.txt    # 依賴套件
├── templates/          # HTML 模板
│   ├── admin/         # 管理後台模板
│   ├── feedback/      # 評估表單模板
│   └── base.html      # 基礎模板
└── static/            # 靜態檔案
```

## 授權說明

本專案採用 MIT 授權條款。詳見 LICENSE 檔案。

## 貢獻指南

歡迎提交 Issue 和 Pull Request 來改進這個專案。

## 聯絡方式

如有任何問題或建議，請透過 GitHub Issues 與我們聯繫。 