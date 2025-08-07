from django.contrib.auth.models import User
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Create a superuser if it does not exist"

    def add_arguments(self, parser):
        parser.add_argument("--username", type=str, help="Username for the superuser")
        parser.add_argument("--email", type=str, help="Email for the superuser")
        parser.add_argument("--password", type=str, help="Password for the superuser")

    def handle(self, *args, **options):
        username = options.get("username", "admin")
        email = options.get("email", "admin@example.com")
        password = options.get("password", "admin123")

        if User.objects.filter(username=username).exists():
            self.stdout.write(
                self.style.WARNING(f'Superuser "{username}" already exists.')
            )
        else:
            User.objects.create_superuser(username, email, password)
            self.stdout.write(
                self.style.SUCCESS(f'Superuser "{username}" created successfully.')
            )
