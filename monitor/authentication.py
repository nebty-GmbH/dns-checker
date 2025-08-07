from django.utils import timezone
from rest_framework import authentication, exceptions

from .models import APIKey


class APIKeyAuthentication(authentication.BaseAuthentication):
    """
    Simple API key authentication.

    Clients should authenticate by passing the API key in the Authorization header:
    Authorization: ApiKey your_api_key_here
    """

    keyword = "ApiKey"

    def authenticate(self, request):
        auth_header = authentication.get_authorization_header(request).split()

        if not auth_header or auth_header[0].lower() != self.keyword.lower().encode():
            return None

        if len(auth_header) == 1:
            msg = "Invalid API key header. No credentials provided."
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth_header) > 2:
            msg = (
                "Invalid API key header. Credentials string should not contain spaces."
            )
            raise exceptions.AuthenticationFailed(msg)

        try:
            key = auth_header[1].decode()
        except UnicodeError:
            msg = "Invalid API key header. Credentials string contains invalid characters."
            raise exceptions.AuthenticationFailed(msg)

        return self.authenticate_credentials(key)

    def authenticate_credentials(self, key):
        try:
            api_key = APIKey.objects.select_related("user").get(key=key, is_active=True)
        except APIKey.DoesNotExist:
            raise exceptions.AuthenticationFailed("Invalid API key.")

        if not api_key.user.is_active:
            raise exceptions.AuthenticationFailed("User account is disabled.")

        # Update last used timestamp
        api_key.last_used = timezone.now()
        api_key.save(update_fields=["last_used"])

        return (api_key.user, api_key)

    def authenticate_header(self, request):
        return self.keyword
