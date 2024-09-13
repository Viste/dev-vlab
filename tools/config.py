import os

import redis


class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'mariadb+pymysql://user:pass@localhost/base?charset=utf8mb4')
    SECRET_KEY = os.getenv('SECRET_KEY', 'super_vlab_secret')
    SQLALCHEMY_ECHO = True
    SQLALCHEMY_POOL_SIZE = 10
    SQLALCHEMY_POOL_TIMEOUT = 30
    SQLALCHEMY_POOL_RECYCLE = 1800
    SQLALCHEMY_MAX_OVERFLOW = 5
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # VKontakte OAuth configuration
    VK_CLIENT_ID = os.getenv('VK_CLIENT_ID')
    VK_CLIENT_SECRET = os.getenv('VK_CLIENT_SECRET')
    TELEGRAM_API_ID = os.getenv('TELEGRAM_API_ID')
    TELEGRAM_API_HASH = os.getenv('TELEGRAM_API_HASH')
    TELEGRAM_BOT_SECRET = os.getenv('TELEGRAM_BOT_SECRET')
    UPLOAD_FOLDER = 'static'
    SESSION_TYPE = 'redis'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'vlab_session:'
    SESSION_REDIS = redis.StrictRedis(host='redis-master.redis.svc.cluster.local', port=6379, db=0)
