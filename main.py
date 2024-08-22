import logging

from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
from aiohttp import web

from app import app
from core.routes import dp, bot

logging.basicConfig(level=logging.INFO)


async def create_app():
    await bot.set_webhook(url="https://dev-vlab.ru/webhook")

    # Создание aiohttp приложения
    aiohttp_app = web.Application()
    aiohttp_app = setup_application(aiohttp_app, SimpleRequestHandler(dispatcher=dp, bot=bot))
    aiohttp_app.router.add_route("*", "/{path_info:.*}", lambda request: app)

    return aiohttp_app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=8000)
