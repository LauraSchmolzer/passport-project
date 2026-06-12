from PKD.parser.ldif_parser import ParseLDIF

from sqlalchemy.orm import sessionmaker, Session

import os
from dotenv import load_dotenv

from pathlib import Path

load_dotenv()
ICAOPKD_ML_PATH = os.getenv('ICAOPKD_ML_PATH')

class PKDimported:
    def __init__(self, ):
        self.session = 0

    def import_pkd_data(self):
    
        with open(ICAOPKD_ML_PATH, "rb") as f:
                ldif_parser = ParseLDIF(f)
                for record in ldif_parser.process_file():
                    
                    
                    
                    # parse further





# --- Execution Block (Streaming Example) ---
if __name__ == "__main__":
    pkd_importer = PKDimported()
    pkd_importer.import_pkd_data()
                    
