"""
This file shows the existing CRL state for a country of choice.
It verifies CRL signatures and shows which DS certs are revoked.
"""

from PKD.db_models import CRL, DSCertificate, CSCACertificate, SessionLocal

COUNTRY = "AL"

def test_crl_graph():
    with SessionLocal() as session:

        crls = (
            session.query(CRL)
            .join(CRL.country)
            .filter(CRL.country.has(code=COUNTRY))
            .order_by(CRL.this_update.asc())
            .all()
        )

        print(f"\n================ CRL STATE FOR {COUNTRY} ================\n")

        if not crls:
            print(f"  No CRLs found for {COUNTRY}")
            return

        for crl in crls:
            print(f"CRL ID:           {crl.id}")
            print(f"  Issuer DN:      {crl.issuer_dn}")
            print(f"  This update:    {crl.this_update}")
            print(f"  Next update:    {crl.next_update}")
            print(f"  AKI:            {crl.aki.hex() if crl.aki else None}")

            if crl.csca_id:
                csca = session.get(CSCACertificate, crl.csca_id)
                print(f"  Issuing CSCA:   {csca.sha256_finger[:16]}...")
                print(f"  CSCA valid:     {csca.not_before.date()} -> {csca.not_after.date()}")
            else:
                print(f"  Issuing CSCA:   NOT LINKED")

            if crl.signature_valid is True:
                print(f"  Signature:      VALID")
            elif crl.signature_valid is False:
                print(f"  Signature:      INVALID")
            else:
                print(f"  Signature:      NOT CHECKED (no issuing CSCA found)")

            revoked = (
                session.query(DSCertificate)
                .filter_by(revoking_crl_id=crl.id)
                .all()
            )

            if revoked:
                print(f"  Revoked DS certs ({len(revoked)}):")
                for ds in revoked:
                    print(f"    serial={ds.serial_number}  revoked_at={ds.revoked_at}  subject={ds.subject_dn[:40]}...")
            else:
                print(f"  Revoked DS certs: none linked yet")

            print("\n------------------------------------------------------------\n")

from PKD.db_models import CRL, SessionLocal

def test_all_crls():
    with SessionLocal() as session:

        crls = (
            session.query(CRL)
            .join(CRL.country)
            .order_by(CRL.country)
            .all()
        )

        print(f"\n================ ALL CRLs ({len(crls)}) ================\n")

        for crl in crls:
            sig = "✓" if crl.signature_valid is True else "✗" if crl.signature_valid is False else "?"
            linked = f"CSCA {crl.csca_id}" if crl.csca_id else "NOT LINKED"
            revoked = crl.ds_certs
            revoked_amount = len(crl.revoked_serials)
            print(f"  {crl.country.code}  |  {sig}  |  {linked}  |  updated {crl.this_update.date()}  |  {crl.issuer_dn[:40]}... | {revoked} | amount revoked {revoked_amount}")

        print(f"\nTotal: {len(crls)}")
        print(f"Valid signatures:   {sum(1 for c in crls if c.signature_valid is True)}")
        print(f"Invalid signatures: {sum(1 for c in crls if c.signature_valid is False)}")
        print(f"Unlinked:          {sum(1 for c in crls if c.csca_id is None)}")


def test_ds_crl_serials():
    with SessionLocal() as session:

        crls = (
            session.query(CRL)
            .join(CRL.country)
            .order_by(CRL.country)
            .all()
        )

        for crl in crls:
            dscerts = (
                session.query(DSCertificate)
                .filter_by(csca_id=crl.csca_id)
                .all()
            )

            ds_serials = [ds.serial_number for ds in dscerts]
            revoked_serials = list(crl.revoked_serials.keys())

            print(f"\n=== {crl.country.code} ===")
            print(f"DS serials ({len(ds_serials)}):")
            for serial in ds_serials:
                print(f"  {serial}")

            print(f"Revoked serials ({len(revoked_serials)}):")
            for serial in revoked_serials:
                print(f"  {serial}")


#test_crl_graph()

#test_all_crls()

test_ds_crl_serials()
 