# 360度績效評估系統

這是一個基於 Flask 開發的 360 度績效評估系統，用於收集和管理員工的多面向績效回饋。

## 功能特點

- 多角色支援（管理員、一般使用者）
- 360度績效評估表單
- 績效目標管理
- 績效回饋分析
- 使用者管理
- 部門管理
- 響應式網頁設計

## 主要功能模組

### 1. 使用者管理
- 使用者帳號管理
- 部門分配
- 權限設定

### 2. 績效目標管理
- 目標設定與追蹤
- 進度管理
- 目標狀態更新

### 3. 360度回饋評估
- 評估任務建立
- 多面向評分
- 文字回饋
- 評估進度追蹤

### 4. 績效分析
- 整體績效分析
- 個人績效分析
- 多維度評分統計
- 圖表視覺化

## 系統需求

- Python 3.8+
- Flask
- SQLAlchemy
- 其他依賴套件（見 requirements.txt）

## 安裝步驟

1. 克隆專案：
```bash
git clone https://github.com/DavidLin729/360-performance-evaluation.git
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
   - 使用者名稱：David
   - 密碼：123456

2. 一般使用者帳號：
   - 需要由管理員建立

## 專案結構

```
360績效管理系統/
├── app.py              # 主應用程式
├── config.py           # 設定檔
├── models.py           # 資料模型
├── requirements.txt    # 依賴套件
├── templates/          # HTML 模板
│   ├── admin/         # 管理後台模板
│   │   ├── analysis.html      # 績效分析頁面
│   │   ├── dashboard.html     # 儀表板
│   │   ├── feedback.html      # 回饋管理
│   │   ├── goals.html         # 目標管理
│   │   ├── performance.html   # 績效管理
│   │   ├── users.html         # 使用者管理
│   │   └── components/        # 共用組件
│   ├── feedback/      # 評估表單模板
│   └── base.html      # 基礎模板
└── static/            # 靜態檔案
```

## 最新更新

- 移除模擬回饋問卷功能
- 統一360問卷任務管理表單格式
- 優化使用者介面
- 新增績效分析功能
- 改進目標管理功能

## 授權說明

本專案採用 MIT 授權條款。詳見 LICENSE 檔案。

## 貢獻指南

歡迎提交 Issue 和 Pull Request 來改進這個專案。

## 聯絡方式

如有任何問題或建議，請透過 GitHub Issues 與我們聯繫。 