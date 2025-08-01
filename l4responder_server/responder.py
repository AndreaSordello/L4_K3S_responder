
import asyncio
import logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')

# Configuration
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 60000
CONNECTION_TIMEOUT = 5.0  # seconds

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    logging.info(f" Connessione da {addr[0]}:{addr[1]}")

    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=CONNECTION_TIMEOUT)
        if data:
            logging.debug(f"Messaggio ricevuto")
        else:
            logging.warning(f" Nessun dato ricevuto da {addr[0]}:{addr[1]}")
    except asyncio.TimeoutError:
        logging.warning(f" Timeout: Nessun messaggio da {addr[0]}:{addr[1]} entro {CONNECTION_TIMEOUT} secondi")
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        logging.warning(f" Connessione chiusa dal client {addr[0]}:{addr[1]}")
    except Exception as e:
        logging.error(f" Errore durante la lettura da {addr[0]}:{addr[1]}: {e}")

    logging.info(f" Chiusura connessione con {addr[0]}:{addr[1]}")
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass



# Start the asyncio server
async def start_server():
    server = await asyncio.start_server(handle_client, LISTEN_IP, LISTEN_PORT)
    addr = server.sockets[0].getsockname()
    logging.info(f"\n Server avviato su {addr[0]}:{addr[1]}\n")

    async with server:
        await server.serve_forever()



#  Entry point
if __name__ == "__main__":
    print("\n" + "="*60)
    print("          L4 NETWORK RESPONDER (ASYNCIO)")
    print("="*60)
    print(f"\nIN ASCOLTO SU: {LISTEN_IP}")
    print(f"TIMEOUT CONNESSIONE: {CONNECTION_TIMEOUT} secondi\n")

    asyncio.run(start_server())