"""
    This file verifies that CSCA certificates imported from ALL Master Lists, 
    a specific SHA-256 hash is uniquely and consistently bound to exactly ONE specific certificate.
    Cross-verification of a certificate being the same is checked my validation date.
"""


from collections import defaultdict
from PKD.db_models import MasterList, CSCACertificate, SessionLocal

def test_cert_hash_integrity():

    with SessionLocal() as session:
        all_certs = session.query(CSCACertificate).all()
        # ___ Check 1: each sha256_finger maps to exactly one row ________________
        hash_to_certs = defaultdict(list)
        for cert in all_certs:
            hash_to_certs[cert.sha256_finger].append(cert)

        collisions = {h: c for h, c in hash_to_certs.items() if len(c) > 1}
        assert not collisions, (
            f"sha256_finger not unique, duplicate rows found for: {list(collisions.keys())}"
        )
        # ___ Check 2: do all MLs that publish a (country, org, not_after) entry _______

        for is_link in (False, True):
            per_ml_sets = defaultdict(dict)

            for ml in session.query(MasterList).all():
                for cert in ml.csca_certs:
                    if cert.is_link_cert != is_link:
                        continue
                    key = (cert.country.code, cert.country.organization, cert.not_after)
                    per_ml_sets[key].setdefault(ml.country.code, set()).add(cert.sha256_finger)

            inconsistent = {}
            for key, ml_map in per_ml_sets.items():
                distinct_sets = {frozenset(s) for s in ml_map.values()}
                if len(distinct_sets) > 1:
                    inconsistent[key] = ml_map

            if inconsistent:
                label = "link" if is_link else "self-signed"
                details = "\n".join(
                    f"  {code}/{org}/{not_after}: {ml_map}\n"
                    for (code, org, not_after), ml_map in inconsistent.items()
                )
                print("=====================================================================")
                print(f"{label} certificate has inconsistency \n {details}\n")

test_cert_hash_integrity()