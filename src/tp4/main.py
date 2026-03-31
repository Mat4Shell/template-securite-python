from src.tp4.utils.config import logger
from src.tp4.utils.session import Session


def main():
    logger.info("Starting TP4 - Crazy Decoder")

    host = "31.220.95.27"
    port = 9002

    session = Session(host, port)

    try:
        session.connect()
        success = session.run()

        if success:
            logger.info("=" * 50)
            logger.info(f"FLAG: {session.get_flag()}")
            logger.info("=" * 50)
        else:
            logger.warning("Could not retrieve the flag. Check server output above.")

    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
    finally:
        session.close()


if __name__ == "__main__":
    main()