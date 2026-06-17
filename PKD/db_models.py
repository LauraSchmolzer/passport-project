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
    ds_certs = relationship("DSCertificate", back_populates="country")
    crls = relationship("CRL", back_populates="country")

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
    subject_dn      = Column(Text, nullable=False)
    issuer_dn       = Column(Text, nullable=False)
    serial_number   = Column(String(128), index=True)
    not_before      = Column(DateTime)
    not_after       = Column(DateTime)
    sha256_finger   = Column(String(64), unique=True, index=True, nullable=False)
    raw_cert        = Column(LargeBinary, nullable=False)

    is_link_cert    = Column(Boolean, default=False)
    # NULL for main roots
    source_cert_id  = Column(Integer, ForeignKey("csca_cert.id"), nullable=True)

    source_certs    = relationship("CSCACertificate", remote_side=[id],  back_populates="link_certs")
    link_certs      = relationship("CSCACertificate", back_populates="source_certs")
    master_lists    = relationship("MasterList", secondary=csca_in_ml, back_populates="csca_certs")
    country         = relationship("Country", back_populates="csca_certs")
    ds_certs        = relationship("DSCertificate", back_populates="issuing_csca")

class CRL(Base):
    __tablename__   = "crl"

    id              = Column(Integer, primary_key=True)
    country_id      = Column(Integer, ForeignKey("country.id"), index=True)
    issuer_dn       = Column(Text, nullable=False)
    this_update     = Column(DateTime)
    next_update     = Column(DateTime)
    raw_crl         = Column(LargeBinary, nullable=False)

    country         = relationship("Country", back_populates="crls")
    ds_certs        = relationship("DSCertificate", back_populates="revoking_crl")
    

class DSCertificate(Base):
    __tablename__   = "ds_cert"

    id              = Column(Integer, primary_key=True)
    country_id      = Column(Integer, ForeignKey("country.id"), index=True)
    csca_id         = Column(Integer, ForeignKey("csca_cert.id"))
    revoking_crl_id = Column(Integer, ForeignKey("crl.id"))
    subject_dn      = Column(Text, nullable=False)
    serial_number   = Column(String(128), unique=True, index=True)
    not_before      = Column(DateTime)
    not_after       = Column(DateTime)
    sha256_finger   = Column(String(64), unique=True, index=True, nullable=False)
    is_revoked      = Column(Boolean, default=False)
    revoked_at      = Column(DateTime)
    raw_cert        = Column(LargeBinary, nullable=False)

    country         = relationship("Country", back_populates="ds_certs") # ds_cert.country.code
    revoking_crl    = relationship("CRL", back_populates="ds_certs") # ds_cert.revoking_crl.this_update
    issuing_csca    = relationship("CSCACertificate", back_populates="ds_certs"
)
    

DATABASE_URL = (os.getenv('DB_URL'))

engine = create_engine(DATABASE_URL )
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)




