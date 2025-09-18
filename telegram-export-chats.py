from telethon import TelegramClient

api_id =  0280476   # substitua pelo seu
api_hash = "c17674dad069b33a677fedf52059803"  # substitua pelo seu

client = TelegramClient("minha_sessao", api_id, api_hash)

async def main():
    async for dialog in client.iter_dialogs():
        if dialog.is_channel:
            if dialog.entity.username:
                print(f"{dialog.name} -> https://t.me/{dialog.entity.username}")
            else:
                print(f"{dialog.name} -> Canal privado (sem link público)")

with client:
    client.loop.run_until_complete(main())
