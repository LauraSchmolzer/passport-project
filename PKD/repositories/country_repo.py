from PKD.db_models import Country

class CountryRepository:
    def __init__(self, session):
        self.session = session

    def get_or_create(self, code: str, organization: str | None = None) -> Country:
        country = (self.session.query(Country)
                   .filter_by(code=code.upper(), organization=organization)
                   .one_or_none()
                   )

        if country:
            return country

        country = Country(
            code=code.upper(),
            name=code.upper(),
            organization=organization,
        )

        self.session.add(country)
        self.session.flush()
        return country