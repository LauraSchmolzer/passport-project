" PostgreSQL database for PKI objects "

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Table, Text, DateTime, LargeBinary, Boolean, UniqueConstraint
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

import os
from dotenv import load_dotenv
load_dotenv()

Base = declarative_base()

csca_in_ml = Table(
    "csca_in_ml",
    Base.metadata,
    Column(
        "csca_id",
        Integer,
        ForeignKey("csca_cert.id"),
        primary_key=True
    ),
    Column(
        "master_list_id",
        Integer,
        ForeignKey("master_list.id"),
        primary_key=True
    ),
)

class Country(Base):
    __tablename__ = "country"

    id          = Column(Integer, primary_key=True)
    code        = Column(String(3), nullable=False, index=True) # Conists of 3 int max
    name        = Column(String(128))                            # Consists of 128 int max
    organization = Column(String(256))  # disambiguates sub-issuers sharing a country code (e.g. CN vs Macau SAR)

    __table_args__ = (UniqueConstraint("code", "organization", name="uq_country_code_org"),)


    master_lists = relationship("MasterList", back_populates="country")
    csca_certs = relationship("CSCACertificate", back_populates="country")


class MasterList(Base):
    __tablename__   = "master_list"

    # To not import the same ML twice
    __table_args__  = (UniqueConstraint("country_id", "sequence_number"),)  # note the comma

    id              = Column(Integer, primary_key=True)
    country_id      = Column(Integer, ForeignKey("country.id"), index=True)
    sequence_number = Column(Integer)
    raw_ml          = Column(LargeBinary)
    sha256_finger   = Column(String(64), unique=True, index=True, nullable=False)

    csca_certs      = relationship("CSCACertificate", secondary=csca_in_ml, back_populates="master_lists")
    country         = relationship("Country", back_populates="master_lists")

class CSCACertificate(Base):
    __tablename__   = "csca_cert"

    id              = Column(Integer, primary_key=True)
    country_id      = Column(Integer, ForeignKey("country.id"), index=True)
    subject_dn      = Column(Text, nullable=False) # Signed
    issuer_dn       = Column(Text, nullable=False) # Signer
    serial_number   = Column(String(128), index=True)
    not_before      = Column(DateTime)
    not_after       = Column(DateTime)
    sha256_finger   = Column(String(64), unique=True, index=True, nullable=False)
    raw_cert        = Column(LargeBinary, nullable=False)

    ski             = Column(LargeBinary, nullable=True)
    aki             = Column(LargeBinary, nullable=True)
    
    is_link_cert    = Column(Boolean, default=False)

    master_lists    = relationship("MasterList", secondary=csca_in_ml, back_populates="csca_certs")
    country         = relationship("Country", back_populates="csca_certs")

class CSCALink(Base):
    __tablename__ = "csca_link"

    id = Column(Integer, primary_key=True)

    from_csca_id = Column(Integer, ForeignKey("csca_cert.id"), index=True)
    to_csca_id = Column(Integer, ForeignKey("csca_cert.id"), index=True)

    link_cert_id = Column(Integer, ForeignKey("csca_cert.id"), unique=True)


DATABASE_URL = (os.getenv('DB_URL'))

engine = create_engine(DATABASE_URL )
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)




