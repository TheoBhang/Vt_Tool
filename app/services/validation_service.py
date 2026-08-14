from app.DataHandler.validator import DataValidator


class ValidationService:
    """Classifies a raw value into DataValidator's type-string vocabulary, or None
    if unsupported/invalid. Thin wrapper - the validation logic itself already
    lives correctly in DataValidator, this just gives it a service-class entry
    point AnalysisService can call without knowing DataValidator's method-naming
    convention."""

    def __init__(self, validator: DataValidator | None = None):
        self.validator = validator or DataValidator()

    def classify(self, value, value_type: str) -> str | None:
        try:
            if value_type == "hashes":
                return self.validator.validate_hash(value)
            validator_func = getattr(self.validator, f"validate_{value_type[:-1]}")
            return validator_func(value)
        except AttributeError:
            return None
