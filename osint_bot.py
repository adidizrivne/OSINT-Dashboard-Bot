#!/usr/bin/env python3
"""
OSINT Dashboard Bot для Telegram
Функції: Sherlock, GeoIP, WHOIS, HaveIBeenPwned, Email Search
"""

import os
import json
import subprocess
import requests
import re
from datetime import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    QueryHandler,
    ContextTypes,
    filters,
)
from telegram.constants import ParseMode
import logging

# Налаштування логування
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

CONFIG_FILE = "osint_config.json"
SHERLOCK_DIR = "sherlock"

class OSINTBot:
    """Основний клас для OSINT функцій"""
    
    def __init__(self):
        self.config = self.load_config()
        self.sherlock_installed = self.check_sherlock()
    
    def load_config(self):
        """Завантажує конфігурацію"""
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        return {
            "api_keys": {
                "ipqualityscore": None,  # Для GeoIP
                "abuseipdb": None,
            }
        }
    
    def save_config(self):
        """Зберігає конфігурацію"""
        with open(CONFIG_FILE, "w") as f:
            json.dump(self.config, f, indent=2)
    
    def check_sherlock(self):
        """Перевіряє наявність Sherlock"""
        try:
            result = subprocess.run(
                ["python3", "-c", "import sherlock"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def sherlock_search(self, username: str) -> dict:
        """
        Пошук користувача через Sherlock
        Повертає словник з результатами
        """
        try:
            # Встановлення Sherlock якщо потрібно
            if not self.sherlock_installed:
                logger.info("Встановлення Sherlock...")
                subprocess.run(
                    ["pip", "install", "sherlock-project", "--quiet"],
                    timeout=60
                )
            
            # Запуск Sherlock
            logger.info(f"Sherlock пошук для: {username}")
            result = subprocess.run(
                ["python3", "-m", "sherlock", username, "--csv", "--print-found"],
                capture_output=True,
                timeout=120,
                text=True
            )
            
            # Парсинг результатів
            results = {
                "found": [],
                "not_found": [],
                "total": 0
            }
            
            if result.stdout:
                for line in result.stdout.split('\n'):
                    if line.strip() and username.lower() in line.lower():
                        results["found"].append(line.strip())
                        results["total"] += 1
            
            return results
        
        except subprocess.TimeoutExpired:
            return {"error": "⏱️ Пошук займає занадто багато часу. Спробуй пізніше."}
        except Exception as e:
            return {"error": f"❌ Помилка Sherlock: {str(e)}"}
    
    def geoip_lookup(self, ip: str) -> dict:
        """
        GeoIP пошук за IP адресою
        Використовує безплатний IP-API
        """
        try:
            if not self.is_valid_ip(ip):
                return {"error": "❌ Невірний IP формат"}
            
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=10,
                params={"fields": "status,country,regionName,city,lat,lon,isp,org,as"}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "success": True,
                        "country": data.get("country"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "as": data.get("as")
                    }
            
            return {"error": "❌ IP не знайдений"}
        
        except requests.Timeout:
            return {"error": "⏱️ Затримка при з'єднанні"}
        except Exception as e:
            return {"error": f"❌ Помилка GeoIP: {str(e)}"}
    
    def whois_lookup(self, domain: str) -> dict:
        """
        WHOIS пошук по доменам
        """
        try:
            if not self.is_valid_domain(domain):
                return {"error": "❌ Невірний формат домену"}
            
            try:
                import whois
            except ImportError:
                subprocess.run(
                    ["pip", "install", "python-whois", "--quiet"],
                    timeout=30
                )
                import whois
            
            domain_info = whois.whois(domain)
            
            return {
                "success": True,
                "domain": domain_info.domain_name,
                "registrar": domain_info.registrar,
                "created": str(domain_info.creation_date),
                "updated": str(domain_info.updated_date),
                "expires": str(domain_info.expiration_date),
                "nameservers": domain_info.name_servers[:3] if domain_info.name_servers else []
            }
        
        except Exception as e:
            return {"error": f"❌ Помилка WHOIS: {str(e)[:100]}"}
    
    def hibp_check(self, email: str) -> dict:
        """
        Перевірка електронної пошти в HaveIBeenPwned
        """
        try:
            if not self.is_valid_email(email):
                return {"error": "❌ Невірна електронна адреса"}
            
            headers = {
                "User-Agent": "OSINT-Bot/1.0"
            }
            
            response = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                breaches = response.json()
                return {
                    "success": True,
                    "breached": True,
                    "count": len(breaches),
                    "breaches": [b.get("Name") for b in breaches[:5]]
                }
            elif response.status_code == 404:
                return {"success": True, "breached": False}
            else:
                return {"error": f"API помилка: {response.status_code}"}
        
        except requests.Timeout:
            return {"error": "⏱️ Затримка при з'єднанні до HIBP"}
        except Exception as e:
            return {"error": f"❌ Помилка HIBP: {str(e)}"}
    
    def email_search(self, email: str) -> dict:
        """
        Пошук електронної пошти у публічних базах
        """
        try:
            if not self.is_valid_email(email):
                return {"error": "❌ Невірна електронна адреса"}
            
            # Використовуємо EmailRep API (безплатний)
            response = requests.get(
                f"https://emailrep.io/{email}",
                timeout=10,
                params={"key": "affc3d2d96f198e92e58750cfc2a8ff311e23076"}
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "reputation": data.get("reputation"),
                    "suspicious": data.get("suspicious"),
                    "details": {
                        "deliverable": data.get("details", {}).get("deliverable"),
                        "valid_format": data.get("details", {}).get("valid_format"),
                        "ask_for_credentials": data.get("details", {}).get("ask_for_credentials")
                    }
                }
            
            return {"error": "❌ Email не знайдений"}
        
        except Exception as e:
            return {"error": f"❌ Помилка Email Search: {str(e)[:100]}"}
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Перевірка IP формату"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(pattern, ip))
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Перевірка домену"""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Перевірка email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))


class TelegramBot:
    """Телеграм бот"""
    
    def __init__(self, token: str):
        self.token = token
        self.osint = OSINTBot()
        self.user_states = {}
    
    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Стартова команда"""
        keyboard = [
            [InlineKeyboardButton("🔍 Sherlock (Username)", callback_data="sherlock")],
            [InlineKeyboardButton("🌍 GeoIP (IP Адреса)", callback_data="geoip")],
            [InlineKeyboardButton("🏢 WHOIS (Домен)", callback_data="whois")],
            [InlineKeyboardButton("🔓 HaveIBeenPwned (Email)", callback_data="hibp")],
            [InlineKeyboardButton("📧 Email Search", callback_data="email_search")],
            [InlineKeyboardButton("ℹ️ Про бот", callback_data="about")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "👋 Добро пожалувати до <b>OSINT Dashboard Bot</b>!\n\n"
            "Цей бот допоможе тобі знайти інформацію про:\n"
            "• Користувачів (username)\n"
            "• IP адреси\n"
            "• Домени\n"
            "• Скомпрометовані емейли\n\n"
            "Обери опцію нижче:",
            parse_mode=ParseMode.HTML,
            reply_markup=reply_markup
        )
    
    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обробка натискання кнопок"""
        query = update.callback_query
        await query.answer()
        
        user_id = query.from_user.id
        choice = query.data
        
        self.user_states[user_id] = choice
        
        if choice == "about":
            await query.edit_message_text(
                text="<b>OSINT Dashboard Bot v1.0</b>\n\n"
                "Функції:\n"
                "🔍 <b>Sherlock</b> - Пошук username на 300+ сайтах\n"
                "🌍 <b>GeoIP</b> - Геолокація за IP\n"
                "🏢 <b>WHOIS</b> - Інформація про домени\n"
                "🔓 <b>HIBP</b> - Перевірка скомпрометованих емейлів\n"
                "📧 <b>Email Search</b> - Пошук емейлів у базах\n\n"
                "⚠️ <b>Відповідальне використання:</b>\n"
                "Використовуй цей бот тільки для законних цілей!\n"
                "Порушення приватності карається законом.",
                parse_mode=ParseMode.HTML
            )
            return
        
        # Запит даних у користувача
        prompts = {
            "sherlock": "Введи username для пошуку (напр. john_doe):",
            "geoip": "Введи IP адресу для геолокації (напр. 8.8.8.8):",
            "whois": "Введи домен для WHOIS пошуку (напр. example.com):",
            "hibp": "Введи email для перевірки HaveIBeenPwned:",
            "email_search": "Введи email для пошуку:"
        }
        
        await query.edit_message_text(
            text=prompts.get(choice, "Введи значення:")
        )
    
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обробка повідомлень від користувача"""
        user_id = update.message.from_user.id
        query = update.message.text.strip()
        
        if user_id not in self.user_states:
            await update.message.reply_text("❌ Спочатку обери опцію командою /start")
            return
        
        choice = self.user_states[user_id]
        
        # Показуємо статус обробки
        status_msg = await update.message.reply_text("⏳ Обробка запиту...")
        
        try:
            result = None
            
            if choice == "sherlock":
                result = self.osint.sherlock_search(query)
            elif choice == "geoip":
                result = self.osint.geoip_lookup(query)
            elif choice == "whois":
                result = self.osint.whois_lookup(query)
            elif choice == "hibp":
                result = self.osint.hibp_check(query)
            elif choice == "email_search":
                result = self.osint.email_search(query)
            
            # Форматування результатів
            response = self.format_result(choice, result)
            
            # Видаляємо статус повідомлення
            await status_msg.delete()
            
            # Відправляємо результати
            await update.message.reply_text(
                response,
                parse_mode=ParseMode.HTML
            )
            
            # Пропонуємо новий пошук
            keyboard = [
                [InlineKeyboardButton("🔙 Назад до меню", callback_data="start")]
            ]
            await update.message.reply_text(
                "Хочеш виконати ще один пошук?",
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
        
        except Exception as e:
            await status_msg.delete()
            await update.message.reply_text(f"❌ Помилка: {str(e)[:200]}")
    
    def format_result(self, query_type: str, result: dict) -> str:
        """Форматування результатів для Telegram"""
        
        if "error" in result:
            return result["error"]
        
        if query_type == "sherlock":
            if "error" in result:
                return result["error"]
            
            found_count = len(result.get("found", []))
            text = f"<b>🔍 Sherlock Результати:</b>\n\n"
            
            if found_count > 0:
                text += f"✅ <b>Знайдено профілів: {found_count}</b>\n\n"
                for site in result["found"][:10]:  # Макс 10 результатів
                    text += f"• {site}\n"
            else:
                text += "❌ Профілі не знайдені\n"
            
            return text
        
        elif query_type == "geoip":
            if not result.get("success"):
                return result.get("error", "❌ Помилка GeoIP")
            
            return (
                f"<b>🌍 GeoIP Інформація:</b>\n\n"
                f"🌐 <b>Країна:</b> {result.get('country')}\n"
                f"📍 <b>Регіон:</b> {result.get('region')}\n"
                f"🏙️ <b>Місто:</b> {result.get('city')}\n"
                f"📐 <b>Координати:</b> {result.get('latitude')}, {result.get('longitude')}\n"
                f"🔗 <b>ISP:</b> {result.get('isp')}\n"
                f"🏢 <b>Організація:</b> {result.get('org')}\n"
                f"📡 <b>AS:</b> {result.get('as')}\n"
            )
        
        elif query_type == "whois":
            if not result.get("success"):
                return result.get("error", "❌ Помилка WHOIS")
            
            return (
                f"<b>🏢 WHOIS Інформація:</b>\n\n"
                f"🌐 <b>Домен:</b> {result.get('domain')}\n"
                f"📋 <b>Реєстратор:</b> {result.get('registrar')}\n"
                f"📅 <b>Створено:</b> {result.get('created')}\n"
                f"🔄 <b>Оновлено:</b> {result.get('updated')}\n"
                f"⏰ <b>Закінчується:</b> {result.get('expires')}\n"
                f"🔗 <b>NS:</b> {', '.join(result.get('nameservers', []))}\n"
            )
        
        elif query_type == "hibp":
            if not result.get("success"):
                return result.get("error", "❌ Помилка HIBP")
            
            if result.get("breached"):
                breaches = ", ".join(result.get("breaches", []))
                return (
                    f"<b>🔓 HaveIBeenPwned Результат:</b>\n\n"
                    f"⚠️ <b>УВАГА!</b> Цей email був скомпрометований!\n"
                    f"📊 <b>Кількість витоків:</b> {result.get('count')}\n"
                    f"📝 <b>Витоки:</b> {breaches}\n"
                )
            else:
                return (
                    f"<b>🔓 HaveIBeenPwned Результат:</b>\n\n"
                    f"✅ <b>Добра новина!</b> Цей email не був знайдений у витоках.\n"
                )
        
        elif query_type == "email_search":
            if not result.get("success"):
                return result.get("error", "❌ Помилка Email Search")
            
            return (
                f"<b>📧 Email Search Результат:</b>\n\n"
                f"⭐ <b>Репутація:</b> {result.get('reputation')}\n"
                f"🚨 <b>Підозріли:</b> {'Так' if result.get('suspicious') else 'Ні'}\n"
                f"📬 <b>Доставляється:</b> {'Так' if result.get('details', {}).get('deliverable') else 'Ні'}\n"
                f"✔️ <b>Формат валідний:</b> {'Так' if result.get('details', {}).get('valid_format') else 'Ні'}\n"
            )
        
        return "❌ Невідомий тип запиту"
    
    def run(self):
        """Запуск бота"""
        app = Application.builder().token(self.token).build()
        
        # Обробники команд
        app.add_handler(CommandHandler("start", self.start))
        
        # Обробник кнопок
        app.add_handler(QueryHandler(self.button_callback))
        
        # Обробник звичайних повідомлень
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))
        
        logger.info("✅ Бот запущено!")
        app.run_polling()


def main():
    """Точка входу"""
    print("=" * 50)
    print("🤖 OSINT Dashboard Bot для Telegram")
    print("=" * 50)
    
    token = os.getenv("TELEGRAM_BOT_TOKEN") or input("\n🔑 Введи Telegram Bot Token: ").strip()
    
    if not token:
        print("❌ Bot Token не знайдений!")
        return
    
    bot = TelegramBot(token)
    bot.run()


if __name__ == "__main__":
    main()
