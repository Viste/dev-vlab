import os


class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'mariadb+pymysql://user:pass@localhost/base?charset=utf8mb4')
    SECRET_KEY = os.getenv('SECRET_KEY', 'super_vlab_secret')
    SQLALCHEMY_ECHO = True
    SQLALCHEMY_POOL_SIZE = 10
    SQLALCHEMY_POOL_TIMEOUT = 30
    SQLALCHEMY_POOL_RECYCLE = 1800
    SQLALCHEMY_MAX_OVERFLOW = 5
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    TELEGRAM_BOT_TOKEN = os.getenv('TG_BOT_TOKEN')
    TELEGRAM_BOT_NAME = 'dev_vlab_bot'

    # VKontakte OAuth configuration
    VK_CLIENT_ID = os.getenv('VK_CLIENT_ID')
    VK_CLIENT_SECRET = os.getenv('VK_CLIENT_SECRET')
    VK_REDIRECT_URI = os.getenv('VK_REDIRECT_URI', 'http://localhost:5000/vk/authorize')
