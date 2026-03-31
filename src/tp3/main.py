from src.tp3.utils.captcha import CaptchaOCR, CaptchaLeak, CaptchaEmpty
from src.tp3.utils.config import logger
from src.tp3.utils.session import Session


def main():
    logger.info("Starting TP3 - Captcha Solver")

    ip = "31.220.95.27:9002"

    challenges = {
        "1": {
            "url": f"http://{ip}/captcha1/",
            "captcha_class": CaptchaOCR,
            "flag_min": 1000,
            "flag_max": 2000,
        },
        "2": {
            "url": f"http://{ip}/captcha2/",
            "captcha_class": CaptchaLeak,
            "flag_min": 2000,
            "flag_max": 3000,
        },
        "3": {
            "url": f"http://{ip}/captcha3/",
            "captcha_class": CaptchaOCR,
            "flag_min": 3000,
            "flag_max": 4000,
        },
        "4": {
            "url": f"http://{ip}/captcha4/",
            "captcha_class": CaptchaEmpty,
            "flag_min": 7000,
            "flag_max": 8000,
            "extra_headers": {"Magic-Word": "magic"},
            "reveal_captcha_class": CaptchaOCR,
        },
    }

    for i, cfg in challenges.items():
        url = cfg["url"]
        logger.info(f"Challenge {i} : {url}")

        session = Session(
            url=url,
            captcha_class=cfg["captcha_class"],
            flag_min=cfg["flag_min"],
            flag_max=cfg["flag_max"],
            extra_headers=cfg.get("extra_headers"),
            reveal_captcha_class=cfg.get("reveal_captcha_class"),
        )

        session.prepare_request()
        session.submit_request()

        while not session.process_response():
            session.prepare_request()
            session.submit_request()

        logger.info("Smell good !")
        logger.info(f"Flag for {url} : {session.get_flag()}")


if __name__ == "__main__":
    main()