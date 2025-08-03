import asyncio
import logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')

# Configuration
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 60000
CONNECTION_TIMEOUT = 5.0  # seconds

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    logging.info(f" Connection from {addr[0]}:{addr[1]}")

    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=CONNECTION_TIMEOUT)
        if data:
            logging.debug(f"Message received")
        else:
            logging.warning(f" No data received from {addr[0]}:{addr[1]}")
    except asyncio.TimeoutError:
        logging.warning(f" Timeout: No message from {addr[0]}:{addr[1]} within {CONNECTION_TIMEOUT} seconds")
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        logging.warning(f" Connection closed by client {addr[0]}:{addr[1]}")
    except Exception as e:
        logging.error(f" Error while reading from {addr[0]}:{addr[1]}: {e}")

    logging.info(f" Closing connection with {addr[0]}:{addr[1]}")
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass



# Start the asyncio server
async def start_server():
    server = await asyncio.start_server(handle_client, LISTEN_IP, LISTEN_PORT)
    addr = server.sockets[0].getsockname()
    logging.info(f"\n Server started on {addr[0]}:{addr[1]}\n")

    async with server:
        await server.serve_forever()



# Entry point
if __name__ == "__main__":
    print("\n" + "="*60)
    print("          L4 NETWORK RESPONDER (ASYNCIO)")
    print("="*60)
    print(f"\nLISTENING ON: {LISTEN_IP}")
    print(f"CONNECTION TIMEOUT: {CONNECTION_TIMEOUT} seconds\n")

    asyncio.run(start_server())