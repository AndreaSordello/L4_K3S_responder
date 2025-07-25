
import asyncio
import logging
import netifaces  # ← Make sure this is installed: pip install netifaces
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')

# Configuration
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 60000
CONNECTION_TIMEOUT = 5.0  # seconds


async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    logging.info(f"✅ Connessione da {addr[0]}:{addr[1]}")

    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=CONNECTION_TIMEOUT)
        if data:
            message = data.decode().strip()
            logging.info(f"📥 Messaggio ricevuto: {message}")
        else:
            logging.warning(f"⚠️ Nessun dato ricevuto da {addr[0]}:{addr[1]}")
    except asyncio.TimeoutError:
        logging.warning(f"⏳ Timeout: Nessun messaggio da {addr[0]}:{addr[1]} entro 3 secondi")

    logging.info(f"🔚 Chiusura connessione con {addr[0]}:{addr[1]}")
    writer.close()
    await writer.wait_closed()



# 🚀 Start the asyncio server
async def start_server():
    server = await asyncio.start_server(handle_client, LISTEN_IP, LISTEN_PORT)
    addr = server.sockets[0].getsockname()
    logging.info(f"\n🚀 Server avviato su {addr[0]}:{addr[1]}\n")

    async with server:
        await server.serve_forever()

# 📡 Network interface info
def get_interface_info():
    try:
        interfaces_info = []
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr:
                        interfaces_info.append(f"{iface}: {addr['addr']}")
        return interfaces_info
    except Exception as e:
        logging.error(f"⚠️ Errore nel recupero interfacce: {e}")
        return ["Impossibile recuperare informazioni di rete"]

# 🧠 Entry point
if __name__ == "__main__":
    print("\n" + "="*60)
    print("         🧠 L4 NETWORK RESPONDER (ASYNCIO)")
    print("="*60)
    print("\n📡 INTERFACCE DI RETE:")
    for iface_info in get_interface_info():
        print(f" • {iface_info}")
    print(f"\n🔊 IN ASCOLTO SU: {LISTEN_IP}}")
    print(f"⏰ TIMEOUT CONNESSIONE: {CONNECTION_TIMEOUT} secondi\n")

    asyncio.run(start_server())