"""
This file shows the existing CSCA graph for a country of choice.
It verifies link certificates and reconstructs relationships using CSCALink edges.
"""

from PKD.db_models import CSCACertificate, CSCALink, SessionLocal
from sqlalchemy import or_

COUNTRY = "NO"


def test_cert_linkgraph():
    with SessionLocal() as session:
        # Load CSCA certificates (nodes)
        certs = (
            session.query(CSCACertificate)
            .join(CSCACertificate.country)
            .filter(CSCACertificate.country.has(code=COUNTRY))
            .filter(CSCACertificate.is_link_cert == False)
            .order_by(CSCACertificate.not_before.asc())
            .all()
        )

        print(f"\n================ CSCA LINK CHAIN FOR {COUNTRY} ================\n")

        # Preload all links for this country (edges)
        cert_ids = [c.id for c in certs]

        links = (
            session.query(CSCALink)
            .filter(
                or_(
                    CSCALink.from_csca_id.in_(cert_ids),
                    CSCALink.to_csca_id.in_(cert_ids),
                )
            )
            .all()
        )

        # Index for fast lookup
        outgoing = {}
        incoming = {}

        for l in links:
            outgoing.setdefault(l.from_csca_id, []).append(l)
            incoming.setdefault(l.to_csca_id, []).append(l)

        # Print graph view per CSCA
        for i, csca in enumerate(certs):
            print(f"Generation {i}")
            print(f"  ID:           {csca.id}")
            print(f"  Hash:         {csca.sha256_finger[:16]}...")
            print(f"  Valid:        {csca.not_before.date()} -> {csca.not_after.date()}")
            print(f"  MLs:          {[ml.country.code for ml in csca.master_lists]}")

            out_links = outgoing.get(csca.id, [])
            in_links = incoming.get(csca.id, [])

            if not out_links and not in_links:
                print("  STATUS:       ISOLATED CSCA (no link relations)")

            else:
                if out_links:
                    print("  OUTGOING LINKS:")
                    for link in out_links:
                        target = session.get(CSCACertificate, link.to_csca_id)
                        link_cert = session.get(CSCACertificate, link.link_cert_id)

                        print(f"    goes to {target.sha256_finger[:16]}...")
                        print(f"      via link cert {link_cert.sha256_finger[:16]}...")

                if in_links:
                    print("  INCOMING LINKS:")
                    for link in in_links:
                        source = session.get(CSCACertificate, link.from_csca_id)
                        link_cert = session.get(CSCACertificate, link.link_cert_id)

                        print(f"    comes from {source.sha256_finger[:16]}...")
                        print(f"      via link cert {link_cert.sha256_finger[:16]}...")

            print("\n------------------------------------------------------------\n")


test_cert_linkgraph()