from PKD.db_models import CSCACertificate, SessionLocal


def test_scores():
    with SessionLocal() as session:
        all_certs = (
            session.query(CSCACertificate)
            .filter(CSCACertificate.is_link_cert.is_(False))
            .all()
        )

        scores = {
            "RED": {"countries": set(), "amount": 0},
            "AMBER": {"countries": set(), "amount": 0},
            "GREEN": {"countries": set(), "amount": 0},
        }

        for cert in all_certs:
            if cert.score > 1:
                category = "GREEN"
            elif cert.score == 1:
                category = "AMBER"
            else:
                category = "RED"

            scores[category]["countries"].add(cert.country.code)
            scores[category]["amount"] += 1

        total = len(all_certs)

    print("\n" + "=" * 70)
    print(f"{'CERTIFICATE SCORE REPORT':^70}")
    print("=" * 70)
    print(f"Total certificates checked: {total}\n")

    for colour, data in scores.items():
        amount = data["amount"]
        countries = sorted(data["countries"])
        percentage = (amount / total * 100) if total else 0

        print("-" * 70)
        print(f"{colour:^70}")
        print("-" * 70)
        print(f"Certificates : {amount:>5} ({percentage:5.1f}%)")
        print(f"Countries    : {len(countries):>5}")
        print(f"Country list : {', '.join(countries) if countries else 'None'}")
        print()

    # Find duplicate countries across score categories
    country_scores = {}

    for colour, data in scores.items():
        for country in data["countries"]:
            country_scores.setdefault(country, []).append(colour)

    duplicates = {
        country: colours
        for country, colours in country_scores.items()
        if len(colours) > 1
    }

    print("=" * 70)
    print(f"{'DUPLICATE COUNTRY SCORES':^70}")
    print("=" * 70)

    if duplicates:
        for country, colours in sorted(duplicates.items()):
            print(f"{country:<10} -> {', '.join(colours)}")
    else:
        print("No duplicate countries found.")

    print("=" * 70)
    
test_scores()

