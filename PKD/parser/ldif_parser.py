
from pathlib import Path
from dataclasses import dataclass
from ldif import LDIFParser


@dataclass
class LDIFEntry:
    dn: str
    attributes: dict


class ParseLDIF(LDIFParser):
    def __init__(self, input_file):
        super().__init__(input_file)
        # Removed self.entries to save memory 

    def process_file(self):
        #Streams records one by one from the underlying parser.
        for dn, entry in super().parse():
            # 'yield from' delegates to the handle generator, 
            # passing the yielded LDIFEntry straight through to the caller.
            yield from self.handle(dn, entry)

    def handle(self, dn, entry):
        # Processes a single entry and yields it immediately

        record = LDIFEntry(
            dn=dn,
            attributes=entry
        )
        
        yield record
