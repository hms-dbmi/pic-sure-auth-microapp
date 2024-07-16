package edu.harvard.hms.dbmi.avillach.auth.enums;

public enum PassportValidationResponse {
    // The Visa’s signature is valid, the Visa has not expired, a valid txn claim is present
    VALID,
    // The encoded Visa’s signature failed validation, is missing or incorrect
    INVALID,
    // The Passport payload or Visa parameter is missing
    MISSING,
    // The format of the Passport or Visa is incorrect
    INVALID_PASSPORT,
    // The Visa has expired (as indicated by the “exp” claim)
    VISA_EXPIRED,
    // The Transaction claim (txn) has an error or is missing
    TXN_ERROR,
    // The Expiration claim (exp) has an error or is missing
    EXPIRATION_ERROR,
    // A DB related validation error occurred
    VALIDATION_ERROR,
    // The Visa was expired because the required polling time was exceeded
    EXPIRED_POLLING,
    // There is a change in the dbGaP permissions associated with the user
    PERMISSION_UPDATE
}
