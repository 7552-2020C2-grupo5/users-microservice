"""Constant values and defaults used in multiple modules."""

DEFAULT_SECRET_KEY = "sbv*4Ec&+S7bU_*q4779pymev9p?3VQ9"
DEFAULT_JWT_EXPIRATION = 3600
DEFAULT_JWT_ALGORITHM = "HS256"
DEFAULT_RESET_PWD_EMAIL = "bookbnb.noreply@gmail.com"
DEFAULT_RESET_PWD_LEN = 10

DEFAULT_GOOGLE_OPENID_CFG_URI = (
    "https://accounts.google.com/.well-known/openid-configuration"
)
DEFAULT_GOOGLE_OPENID_CFG_JWKS_KEY = "jwks_uri"
DEFAULT_AUDIENCE = (
    "323498260525-irodasbifo350ic2lftmj226ltink5mp.apps.googleusercontent.com"
)

DEFAULT_VERIFICATION_URL = (
    "https://tokens-microservice.herokuapp.com/v1/tokens/verification"
)
