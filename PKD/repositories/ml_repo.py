from PKD.db_models import MasterList

class MasterListRepository:
    def __init__(self, session):
        self.session = session

    def get_or_create(self, ml_data, country):
        ml = (self.session.query(MasterList)
            .filter_by(sha256_finger=ml_data.sha256_finger)
            .one_or_none()
            )

        if ml:
            return ml

        ml = MasterList(
            sequence_number=1,
            raw_ml=ml_data.raw,
            sha256_finger=ml_data.sha256_finger,
            country=country
        )

        self.session.add(ml)
        self.session.flush()
        return ml