#!/usr/bin/env python3
"""
Setup скрипт для OSINT Dashboard Bot
Автоматичне встановлення та конфігурація
"""

import os
import sys
import subprocess
import json
from pathlib import Path

class BotSetup:
    """Клас для налаштування бота"""
    
    def __init__(self):
        self.config_file = "osint_config.json"
        self.env_file = ".env"
    
    def print_header(self):
        """Вивід заголовка"""
        print("\n" + "=" * 60)
        print("🤖 OSINT Dashboard Bot - Автоматичне Налаштування")
        print("=" * 60 + "\n")
    
    def print_step(self, step: int, total: int, message: str):
        """Вивід кроку"""
        print(f"\n[{step}/{total}] {message}")
        print("-" * 50)
    
    def check_python(self):
        """Перевірка версії Python"""
        version = sys.version_info
        if version.major < 3 or version.minor < 8:
            print("❌ Потрібен Python 3.8+")
            sys.exit(1)
        print(f"✅ Python {version.major}.{version.minor}.{version.micro}")
    
    def install_dependencies(self):
        """Встановлення залежностей"""
        print("\n📦 Встановлення залежностей...")
        
        try:
            subprocess.run(
                ["pip", "install", "-r", "requirements.txt", "--quiet"],
                check=True
            )
            print("✅ Залежності встановлені успішно")
        except subprocess.CalledProcessError:
            print("❌ Помилка при встановленні залежностей")
            print("🔧 Спробуй запустити: pip install -r requirements.txt")
            return False
        
        return True
    
    def get_bot_token(self):
        """Отримання Bot Token від користувача"""
        print("\n🔑 Отримання Telegram Bot Token")
        print("\nКроки:")
        print("1. Відкрий Telegram")
        print("2. Знайди бота @BotFather")
        print("3. Напиши /newbot")
        print("4. Дай назву боту (напр. 'My OSINT Bot')")
        print("5. Дай username (наприклад: 'my_osint_bot')")
        print("6. Скопіюй отриманий token\n")
        
        while True:
            token = input("🔑 Вставь Bot Token: ").strip()
            
            if len(token) < 20:
                print("❌ Токен занадто короткий. Спробуй ще раз.")
                continue
            
            if ":" not in token:
                print("❌ Невірний формат токена. Має містити ':'")
                continue
            
            print(f"✅ Токен отримано: {token[:20]}...")
            return token
        
    def setup_environment(self, token: str):
        """Налаштування файлу .env"""
        with open(self.env_file, "w") as f:
            f.write(f"TELEGRAM_BOT_TOKEN={token}\n")
        print(f"✅ Файл {self.env_file} створено")
    
    def create_config(self):
        """Створення конфігураційного файлу"""
        config = {
            "api_keys": {
                "ipqualityscore": None,
                "abuseipdb": None,
                "hibp": None
            },
            "settings": {
                "sherlock_timeout": 120,
                "request_timeout": 10,
                "max_results": 10
            },
            "created": "2026-03-08",
            "version": "1.0"
        }
        
        with open(self.config_file, "w") as f:
            json.dump(config, f, indent=2)
        
        print(f"✅ Конфігурація створена: {self.config_file}")
    
    def test_bot(self):
        """Тестування підключення бота"""
        print("\n🧪 Тестування підключення...")
        
        token = self.get_env_token()
        if not token:
            print("❌ Токен не знайдений")
            return False
        
        try:
            import requests
            response = requests.get(
                f"https://api.telegram.org/bot{token}/getMe",
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("ok"):
                    bot_info = data.get("result", {})
                    print(f"✅ Бот успішно підключений!")
                    print(f"   Ім'я: @{bot_info.get('username')}")
                    print(f"   ID: {bot_info.get('id')}")
                    return True
        except Exception as e:
            print(f"❌ Помилка підключення: {e}")
        
        return False
    
    def get_env_token(self) -> str:
        """Отримання токена з .env файлу"""
        if os.path.exists(self.env_file):
            with open(self.env_file, "r") as f:
                for line in f:
                    if line.startswith("TELEGRAM_BOT_TOKEN="):
                        return line.split("=", 1)[1].strip()
        return None
    
    def show_next_steps(self):
        """Показ наступних кроків"""
        print("\n" + "=" * 60)
        print("🎉 НАЛАШТУВАННЯ ЗАВЕРШЕНО!")
        print("=" * 60)
        
        print("\n📌 Наступні кроки:\n")
        print("1️⃣  Запусти бота:")
        print("   python3 osint_bot.py\n")
        print("2️⃣  У Telegram:")
        print("   - Знайди свого бота в пошуку")
        print("   - Напиши /start")
        print("   - Обери функцію з меню\n")
        print("3️⃣  Введи свої запити:")
        print("   - Username для Sherlock")
        print("   - IP для GeoIP")
        print("   - Домен для WHOIS")
        print("   - Email для HIBP/Email Search\n")
        
        print("📚 Документація: дивись README.md\n")
        print("⚠️  ВАЖНО: Використовуй бот лише для законних цілей!\n")
        print("=" * 60 + "\n")
    
    def run(self):
        """Запуск налаштування"""
        self.print_header()
        
        # Крок 1: Перевірка Python
        self.print_step(1, 5, "Перевірка Python")
        self.check_python()
        
        # Крок 2: Встановлення залежностей
        self.print_step(2, 5, "Встановлення залежностей")
        if not self.install_dependencies():
            return False
        
        # Крок 3: Отримання токена
        self.print_step(3, 5, "Отримання Telegram Bot Token")
        token = self.get_bot_token()
        
        # Крок 4: Створення файлів
        self.print_step(4, 5, "Створення конфігураційних файлів")
        self.setup_environment(token)
        self.create_config()
        
        # Крок 5: Тестування
        self.print_step(5, 5, "Тестування підключення")
        self.test_bot()
        
        # Показ наступних кроків
        self.show_next_steps()
        
        return True


def main():
    """Точка входу"""
    try:
        setup = BotSetup()
        if setup.run():
            print("✅ Налаштування успішно завершено!\n")
            return 0
        else:
            print("❌ Налаштування не завершено.\n")
            return 1
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Налаштування скасовано користувачем")
        return 1
    except Exception as e:
        print(f"\n❌ Непередбачена помилка: {e}")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
