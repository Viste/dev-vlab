import asyncio
import logging

from aiogram import Dispatcher
from aiogram.dispatcher.middlewares import BaseMiddleware
from aiogram.exceptions import TelegramRetryAfter
from aiogram.types import BotCommand
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
from aiohttp import web

from app import app  # Импорт вашего Flask-приложения
from core.routes import dp, bot  # Импорт диспетчера и бота

logging.basicConfig(level=logging.INFO)


class RetryAfterMiddleware(BaseMiddleware):
    async def __call__(self, handler, event, data):
        try:
            return await handler(event, data)
        except TelegramRetryAfter as e:
            logging.warning(f"Flood control exceeded, retrying in {e.retry_after} seconds")
            await asyncio.sleep(e.retry_after)
            return await handler(event, data)


async def on_startup(dispatcher: Dispatcher):
    # Установка команд бота
    await bot.set_my_commands([BotCommand(command="start", description="Запустить бота")])

    try:
        await bot.set_webhook(url="https://dev-vlab.ru/webhook")
    except TelegramRetryAfter as e:
        logging.warning(f"Flood control exceeded, retrying in {e.retry_after} seconds")
        await asyncio.sleep(e.retry_after)
        await bot.set_webhook(url="https://dev-vlab.ru/webhook")


async def create_app():
    aiohttp_app = web.Application()

    setup_application(aiohttp_app, SimpleRequestHandler(dispatcher=dp, bot=bot))

    aiohttp_app.router.add_route("*", "/{path_info:.*}", lambda request: app)
    dp.startup.register(on_startup)
    dp.update.middleware(RetryAfterMiddleware())

    return aiohttp_app

if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=8000)