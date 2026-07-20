
from PKD.db_models import CSCACertificate, SessionLocal

def test_scores():
    with SessionLocal() as session:
        all_certs = session.query(CSCACertificate).filter(CSCACertificate.is_link_cert == False).all()

        red = set()
        red_amount = 0
        amber = set()
        amber_amount = 0
        green = set()
        green_amount = 0
        total = 0

        for cert in all_certs:
            if cert.score > 1:
                green.add(cert.country.code)
                green_amount += 1
            elif cert.score == 1:
                amber.add(cert.country.code)
                amber_amount += 1
            else:
                red.add(cert.country.code)
                red_amount += 1
            total += 1
        
    print(f" TOTAL CHECKED {total}")
    
    print(f"RED TOTAL {red_amount} COUNTRIES {len(red)} : {sorted(red)}")
    print(f"AMBER TOTAL {amber_amount} COUNTRIES {len(amber)} : {sorted(amber)}")
    print(f"GREEN TOTAL {green_amount} COUNTRIES {len(green)} : {sorted(green)}")

    print(f"Only in Amber, not in Green: {sorted(amber.difference(green))}")


            
test_scores()

