from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("monitor", "0008_ipwhoisinfo_recordlogipinfo"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="domain",
            index=models.Index(fields=["is_active"], name="monitor_dom_is_active_idx"),
        ),
        migrations.AddIndex(
            model_name="domain",
            index=models.Index(fields=["updated_at"], name="monitor_dom_updated_idx"),
        ),
        migrations.AddIndex(
            model_name="domain",
            index=models.Index(fields=["created_at"], name="monitor_dom_created_idx"),
        ),
    ]
