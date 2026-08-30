import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class Config:
    DEBUG = True
    SECRET_KEY = os.environ.get('SECRET_KEY', 'threatlens-secret-key')
    # API keys come from the .env file (never commit real keys to source code)
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    NVD_API_KEY = os.environ.get('NVD_API_KEY', '')
    CERTSPOTTER_API_KEY = os.environ.get('CERTSPOTTER_API_KEY', '')
