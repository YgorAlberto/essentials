import os
from telethon import TelegramClient

# ========= CONFIGURAÇÕES =========
api_id = 0280476   # coloque aqui seu API ID (my.telegram.org)
api_hash = "c17674dad069b33a677fedf52059803"  # coloque aqui seu API HASH
download_path = "/home/seuusuario/telegram_txts"  # caminho onde salvar os arquivos
session_name = "minha_sessao"  # nome do arquivo de sessão que será criado
# =================================

# Cria a pasta se não existir
os.makedirs(download_path, exist_ok=True)

# Inicia cliente
client = TelegramClient(session_name, api_id, api_hash)

async def main():
    # Itera sobre todos os diálogos (chats, grupos, canais)
    async for dialog in client.iter_dialogs():
        entity = dialog.entity
        print(f"[+] Verificando: {dialog.name}")

        # Itera sobre mensagens do chat
        async for message in client.iter_messages(entity, limit=None):
            if message.file and message.file.name:
                # Se for TXT
                if message.file.name.lower().endswith(".txt"):
                    print(f"   -> Baixando: {message.file.name}")
                    await message.download_media(file=os.path.join(download_path, message.file.name))

with client:
    client.loop.run_until_complete(main())
